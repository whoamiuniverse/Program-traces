/// @file test_recovery_orchestrator.cpp
/// @brief Orchestrator-level tests for recovery stage runner.

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/orchestrator/recovery_stage_runner.hpp"

namespace {

using WindowsDiskAnalysis::IRecoveryAnalyzer;
using WindowsDiskAnalysis::ProcessInfo;
using WindowsDiskAnalysis::RecoveryEvidence;
using WindowsDiskAnalysis::Orchestrator::RecoveryStage::RecoveryAnalyzerRef;
using WindowsDiskAnalysis::Orchestrator::RecoveryStage::RecoveryStageSlot;

class FakeRecoveryAnalyzer final : public IRecoveryAnalyzer {
 public:
  explicit FakeRecoveryAnalyzer(std::vector<RecoveryEvidence> output,
                                bool should_throw = false,
                                int delay_ms = 0)
      : output_(std::move(output)),
        should_throw_(should_throw),
        delay_ms_(delay_ms) {}

  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& /*disk_root*/) const override {
    if (delay_ms_ > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms_));
    }
    if (should_throw_) {
      throw std::runtime_error("synthetic recovery failure");
    }
    return output_;
  }

 private:
  std::vector<RecoveryEvidence> output_;
  bool should_throw_ = false;
  int delay_ms_ = 0;
};

struct AnalyzerEntry {
  std::string label;
  std::unique_ptr<IRecoveryAnalyzer> analyzer;
};

RecoveryEvidence makeEvidence(const std::string& path,
                              const std::string& source,
                              const std::string& recovered_from,
                              const std::string& details = {}) {
  RecoveryEvidence ev;
  ev.executable_path = path;
  ev.source = source;
  ev.recovered_from = recovered_from;
  ev.timestamp = "2026-04-16T00:00:00Z";
  ev.details = details;
  return ev;
}

std::vector<RecoveryAnalyzerRef> makeAnalyzerRefs(
    const std::vector<AnalyzerEntry>& entries) {
  std::vector<RecoveryAnalyzerRef> refs;
  refs.reserve(entries.size());
  for (const auto& entry : entries) {
    refs.push_back({entry.label, entry.analyzer.get()});
  }
  return refs;
}

const RecoveryStageSlot* findSlotByLabel(
    const std::vector<RecoveryStageSlot>& slots, const std::string& label) {
  for (const auto& slot : slots) {
    if (slot.label == label) {
      return &slot;
    }
  }
  return nullptr;
}

}  // namespace

TEST(RecoveryOrchestratorTest, PartialFailuresStillProduceMergedOutput) {
  std::vector<AnalyzerEntry> analyzers;
  analyzers.push_back({"USN", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\Windows\\System32\\usn.exe",
                                      "USN", "USN.native")})});
  analyzers.push_back(
      {"VSS", std::make_unique<FakeRecoveryAnalyzer>(
                  std::vector<RecoveryEvidence>{}, true)});
  analyzers.push_back({"Hiber", std::make_unique<FakeRecoveryAnalyzer>(
                                    std::vector<RecoveryEvidence>{makeEvidence(
                                        "C:\\Windows\\System32\\hiber.exe",
                                        "Hiber", "Hiber.pool")})});
  analyzers.push_back(
      {"NTFS", std::make_unique<FakeRecoveryAnalyzer>(
                   std::vector<RecoveryEvidence>{}, true)});
  analyzers.push_back({"Registry", std::make_unique<FakeRecoveryAnalyzer>(
                                       std::vector<RecoveryEvidence>{makeEvidence(
                                           "C:\\Windows\\System32\\reg.exe",
                                           "RegistryLog",
                                           "RegistryLog(LOG1)")})});
  analyzers.push_back({"SigScan",
                       std::make_unique<FakeRecoveryAnalyzer>(
                           std::vector<RecoveryEvidence>{})});
  analyzers.push_back({"TSK", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\Windows\\System32\\tsk.exe",
                                      "TSK", "TSK.deleted")})});

  const auto refs = makeAnalyzerRefs(analyzers);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      ensureMandatoryRecoveryAnalyzersRegistered(refs);

  auto slots = WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      createRecoveryStageSlots(refs);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      runRecoveryStageCollectorsSequentially(refs, "/tmp", slots);

  const auto* vss_slot = findSlotByLabel(slots, "VSS");
  ASSERT_NE(vss_slot, nullptr);
  EXPECT_EQ(vss_slot->error_count, 1u);
  const auto* ntfs_slot = findSlotByLabel(slots, "NTFS");
  ASSERT_NE(ntfs_slot, nullptr);
  EXPECT_EQ(ntfs_slot->error_count, 1u);

  std::unordered_map<std::string, ProcessInfo> process_data;
  std::vector<RecoveryEvidence> merged;
  const std::string summary =
      WindowsDiskAnalysis::Orchestrator::RecoveryStage::
          mergeRecoveryEvidenceResults(slots, process_data, merged);

  EXPECT_EQ(merged.size(), 4u);
  EXPECT_EQ(process_data.size(), 4u);
  EXPECT_NE(summary.find("VSS{count=0,errors=1"), std::string::npos);
  EXPECT_NE(summary.find("NTFS{count=0,errors=1"), std::string::npos);
}

TEST(RecoveryOrchestratorTest, FullFallbackPathMergesAllMandatoryModules) {
  std::vector<AnalyzerEntry> analyzers;
  analyzers.push_back({"USN", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\fallback\\usn.exe", "USN",
                                      "USN($LogFile)")})});
  analyzers.push_back({"VSS", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\fallback\\vss.exe", "VSS",
                                      "VSS(unallocated_binary)")})});
  analyzers.push_back({"Hiber", std::make_unique<FakeRecoveryAnalyzer>(
                                    std::vector<RecoveryEvidence>{makeEvidence(
                                        "C:\\fallback\\hiber.exe", "Hiber",
                                        "Hiber(pool)")})});
  analyzers.push_back(
      {"NTFS", std::make_unique<FakeRecoveryAnalyzer>(
                   std::vector<RecoveryEvidence>{makeEvidence(
                       "C:\\fallback\\ntfs.exe", "NTFSMetadata",
                       "NTFSMetadata(bitmap_binary)")})});
  analyzers.push_back({"Registry", std::make_unique<FakeRecoveryAnalyzer>(
                                       std::vector<RecoveryEvidence>{makeEvidence(
                                           "C:\\fallback\\registry.exe",
                                           "RegistryLog",
                                           "RegistryLog(LOG2)")})});
  analyzers.push_back({"SigScan", std::make_unique<FakeRecoveryAnalyzer>(
                                      std::vector<RecoveryEvidence>{makeEvidence(
                                          "C:\\fallback\\sigscan.exe",
                                          "SignatureScan",
                                          "SignatureScan(signature)")})});
  analyzers.push_back({"TSK", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\fallback\\tsk.exe", "TSK",
                                      "TSK(unallocated)")})});

  const auto refs = makeAnalyzerRefs(analyzers);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      ensureMandatoryRecoveryAnalyzersRegistered(refs);

  auto slots = WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      createRecoveryStageSlots(refs);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      runRecoveryStageCollectorsSequentially(refs, "/tmp", slots);

  std::unordered_map<std::string, ProcessInfo> process_data;
  std::vector<RecoveryEvidence> merged;
  const std::string summary =
      WindowsDiskAnalysis::Orchestrator::RecoveryStage::
          mergeRecoveryEvidenceResults(slots, process_data, merged);

  EXPECT_EQ(merged.size(), 7u);
  EXPECT_EQ(process_data.size(), 7u);
  for (const auto& ev : merged) {
    EXPECT_FALSE(ev.source.empty());
    EXPECT_FALSE(ev.recovered_from.empty());
  }
  for (const std::string label :
       {"USN", "VSS", "Hiber", "NTFS", "Registry", "SigScan", "TSK"}) {
    EXPECT_NE(summary.find(label + "{count=1,errors=0"), std::string::npos);
  }
}

TEST(RecoveryOrchestratorTest, ParallelAndSequentialRunsHaveParity) {
  std::vector<AnalyzerEntry> analyzers;
  analyzers.push_back({"USN", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\parity\\usn.exe", "USN",
                                      "USN.native")}, false, 40)});
  analyzers.push_back({"VSS", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\parity\\vss.exe", "VSS",
                                      "VSS.snapshot_binary")}, false, 5)});
  analyzers.push_back({"Hiber", std::make_unique<FakeRecoveryAnalyzer>(
                                    std::vector<RecoveryEvidence>{makeEvidence(
                                        "C:\\parity\\hiber.exe", "Hiber",
                                        "Hiber.pool")}, false, 20)});
  analyzers.push_back({"NTFS", std::make_unique<FakeRecoveryAnalyzer>(
                                   std::vector<RecoveryEvidence>{makeEvidence(
                                       "C:\\parity\\ntfs.exe", "NTFS",
                                       "NTFS.bitmap_binary")}, false, 10)});
  analyzers.push_back(
      {"Registry", std::make_unique<FakeRecoveryAnalyzer>(
                       std::vector<RecoveryEvidence>{makeEvidence(
                           "C:\\parity\\registry.exe", "RegistryLog",
                           "RegistryLog.LOG1")}, false, 30)});
  analyzers.push_back({"SigScan", std::make_unique<FakeRecoveryAnalyzer>(
                                      std::vector<RecoveryEvidence>{makeEvidence(
                                          "C:\\parity\\sigscan.exe",
                                          "SignatureScan",
                                          "SignatureScan.signature")}, false,
                                      15)});
  analyzers.push_back({"TSK", std::make_unique<FakeRecoveryAnalyzer>(
                                  std::vector<RecoveryEvidence>{makeEvidence(
                                      "C:\\parity\\tsk.exe", "TSK",
                                      "TSK.unallocated")}, false, 25)});

  const auto refs = makeAnalyzerRefs(analyzers);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      ensureMandatoryRecoveryAnalyzersRegistered(refs);

  auto sequential_slots = WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      createRecoveryStageSlots(refs);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      runRecoveryStageCollectorsSequentially(refs, "/tmp", sequential_slots);
  std::unordered_map<std::string, ProcessInfo> sequential_process_data;
  std::vector<RecoveryEvidence> sequential_merged;
  const auto sequential_summary =
      WindowsDiskAnalysis::Orchestrator::RecoveryStage::mergeRecoveryEvidenceResults(
          sequential_slots, sequential_process_data, sequential_merged);

  auto parallel_slots = WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      createRecoveryStageSlots(refs);
  WindowsDiskAnalysis::Orchestrator::RecoveryStage::
      runRecoveryStageCollectorsInParallel(refs, "/tmp", parallel_slots);
  std::unordered_map<std::string, ProcessInfo> parallel_process_data;
  std::vector<RecoveryEvidence> parallel_merged;
  const auto parallel_summary =
      WindowsDiskAnalysis::Orchestrator::RecoveryStage::mergeRecoveryEvidenceResults(
          parallel_slots, parallel_process_data, parallel_merged);

  EXPECT_FALSE(sequential_summary.empty());
  EXPECT_FALSE(parallel_summary.empty());

  ASSERT_EQ(sequential_merged.size(), parallel_merged.size());
  for (std::size_t i = 0; i < sequential_merged.size(); ++i) {
    EXPECT_EQ(std::tie(sequential_merged[i].executable_path,
                       sequential_merged[i].source,
                       sequential_merged[i].recovered_from,
                       sequential_merged[i].timestamp,
                       sequential_merged[i].details),
              std::tie(parallel_merged[i].executable_path,
                       parallel_merged[i].source,
                       parallel_merged[i].recovered_from,
                       parallel_merged[i].timestamp,
                       parallel_merged[i].details));
  }
  EXPECT_EQ(sequential_process_data.size(), parallel_process_data.size());

  for (const std::string label :
       {"USN", "VSS", "Hiber", "NTFS", "Registry", "SigScan", "TSK"}) {
    const auto* seq_slot = findSlotByLabel(sequential_slots, label);
    const auto* par_slot = findSlotByLabel(parallel_slots, label);
    ASSERT_NE(seq_slot, nullptr);
    ASSERT_NE(par_slot, nullptr);
    EXPECT_EQ(seq_slot->error_count, 0u);
    EXPECT_EQ(par_slot->error_count, 0u);
    EXPECT_EQ(seq_slot->evidence.size(), par_slot->evidence.size());
  }
}
