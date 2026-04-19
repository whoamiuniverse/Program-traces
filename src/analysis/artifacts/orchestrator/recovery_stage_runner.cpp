/// @file recovery_stage_runner.cpp
/// @brief Implementation of recovery-stage orchestration helpers.

#include "recovery_stage_runner.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <future>
#include <iterator>
#include <tuple>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/data/recovery_contract.hpp"
#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace WindowsDiskAnalysis::Orchestrator::RecoveryStage {

using namespace Orchestrator::Detail;

namespace {

template <typename T>
void appendMovedVector(std::vector<T>& destination, std::vector<T>& source) {
  if (source.empty()) {
    return;
  }

  destination.reserve(destination.size() + source.size());
  destination.insert(destination.end(),
                     std::make_move_iterator(source.begin()),
                     std::make_move_iterator(source.end()));
}

bool hasRecoveryAnalyzer(const std::vector<RecoveryAnalyzerRef>& analyzers,
                         const std::string_view label) {
  for (const auto& analyzer : analyzers) {
    if (analyzer.label == label) {
      return true;
    }
  }
  return false;
}

void appendRecoverySummaryItem(std::string& summary, const std::string_view label,
                               const std::size_t evidence_count,
                               const std::size_t error_count,
                               const std::uint64_t duration_ms) {
  if (!summary.empty()) {
    summary += ", ";
  }
  summary += label;
  summary += "{count=" + std::to_string(evidence_count);
  summary += ",errors=" + std::to_string(error_count);
  summary += ",time_ms=" + std::to_string(duration_ms);
  summary.push_back('}');
}

void sortRecoveryEvidenceDeterministically(
    std::vector<RecoveryEvidence>& evidence) {
  // Sort by stable fields only — details contains offsets/entropy that
  // may differ between runs, so excluding it ensures deterministic order.
  std::stable_sort(evidence.begin(), evidence.end(),
            [](const RecoveryEvidence& lhs, const RecoveryEvidence& rhs) {
              return std::tie(lhs.executable_path, lhs.source,
                              lhs.recovered_from, lhs.timestamp) <
                     std::tie(rhs.executable_path, rhs.source,
                              rhs.recovered_from, rhs.timestamp);
            });
}

}  // namespace

void ensureMandatoryRecoveryAnalyzersRegistered(
    const std::vector<RecoveryAnalyzerRef>& analyzers) {
  static constexpr std::array<std::string_view, 7> kMandatoryAnalyzers = {
      "USN", "VSS", "Hiber", "NTFS", "Registry", "SigScan", "TSK"};

  std::string missing;
  for (const auto label : kMandatoryAnalyzers) {
    if (hasRecoveryAnalyzer(analyzers, label)) {
      continue;
    }
    if (!missing.empty()) {
      missing += ", ";
    }
    missing.append(label);
  }

  if (!missing.empty()) {
    throw DiskAnalyzerException(
        "Recovery pipeline не покрывает обязательный минимум: отсутствуют " +
        missing);
  }
}

std::vector<RecoveryStageSlot> createRecoveryStageSlots(
    const std::vector<RecoveryAnalyzerRef>& analyzers) {
  std::vector<RecoveryStageSlot> slots;
  slots.reserve(analyzers.size());
  for (const auto& analyzer : analyzers) {
    slots.push_back({analyzer.label, {}, 0, 0});
  }
  return slots;
}

void runRecoveryStageCollectorsInParallel(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  using Clock = std::chrono::steady_clock;
  struct Task {
    std::size_t index = 0;
    Clock::time_point started_at{};
    std::future<std::vector<RecoveryEvidence>> future;
  };

  const auto logger = GlobalLogger::get();
  std::vector<Task> tasks;
  tasks.reserve(analyzers.size());

  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    const IRecoveryAnalyzer* ptr = analyzers[i].analyzer;
    tasks.push_back(
        {i, Clock::now(),
         std::async(std::launch::async,
                    [ptr, &disk_root] { return ptr->collect(disk_root); })});
  }

  for (auto& task : tasks) {
    auto& slot = per_analyzer[task.index];
    try {
      slot.evidence = task.future.get();
    } catch (const std::exception& e) {
      slot.error_count++;
      logger->error("Recovery({}): ошибка этапа", slot.label);
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug, "Recovery({}) exception: {}",
                  slot.label, e.what());
    } catch (...) {
      slot.error_count++;
      logger->error("Recovery({}): неизвестная ошибка этапа", slot.label);
    }
    slot.duration_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - task.started_at)
            .count());
  }
}

void runRecoveryStageCollectorsSequentially(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  using Clock = std::chrono::steady_clock;
  const auto logger = GlobalLogger::get();
  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    auto& slot = per_analyzer[i];
    const auto started_at = Clock::now();
    try {
      slot.evidence = analyzers[i].analyzer->collect(disk_root);
    } catch (const std::exception& e) {
      slot.error_count++;
      logger->error("Recovery({}): ошибка этапа", slot.label);
      logger->log(
          spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
          spdlog::level::debug, "Recovery({}) exception: {}", slot.label,
          e.what());
    } catch (...) {
      slot.error_count++;
      logger->error("Recovery({}): неизвестная ошибка этапа", slot.label);
    }
    slot.duration_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - started_at)
            .count());
  }
}

std::string mergeRecoveryEvidenceResults(
    std::vector<RecoveryStageSlot>& per_analyzer,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<RecoveryEvidence>& recovery_evidence) {
  std::string summary;
  summary.reserve(per_analyzer.size() * 24);

  // Cross-analyzer dedup: same executable_path + source should not appear
  // from multiple analyzers (e.g. USN vs SignatureScan for the same exe).
  std::unordered_set<std::string> cross_dedup;

  for (auto& slot : per_analyzer) {
    RecoveryContract::canonicalizeRecoveryEvidence(slot.evidence);
    sortRecoveryEvidenceDeterministically(slot.evidence);
    appendRecoverySummaryItem(summary, slot.label, slot.evidence.size(),
                              slot.error_count, slot.duration_ms);
    mergeRecoveryEvidenceToProcessData(slot.evidence, process_data);

    for (auto& ev : slot.evidence) {
      std::string key = toLowerAscii(ev.executable_path) + "|" + ev.source;
      if (cross_dedup.insert(std::move(key)).second) {
        recovery_evidence.push_back(std::move(ev));
      }
    }
    slot.evidence.clear();
  }
  sortRecoveryEvidenceDeterministically(recovery_evidence);

  return summary;
}

}  // namespace WindowsDiskAnalysis::Orchestrator::RecoveryStage
