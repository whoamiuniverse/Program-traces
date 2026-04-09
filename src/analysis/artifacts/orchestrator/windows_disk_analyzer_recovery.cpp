/// @file windows_disk_analyzer_recovery.cpp
/// @brief Recovery-stage реализация WindowsDiskAnalyzer.

#include "windows_disk_analyzer.hpp"

#include <array>
#include <future>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace WindowsDiskAnalysis {

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

struct RecoveryAnalyzerRef {
  std::string_view label;
  const IRecoveryAnalyzer* analyzer = nullptr;
};

struct RecoveryStageSlot {
  std::string_view label;
  std::vector<RecoveryEvidence> evidence;
};

bool hasRecoveryAnalyzer(const std::vector<RecoveryAnalyzerRef>& analyzers,
                         const std::string_view label) {
  for (const auto& analyzer : analyzers) {
    if (analyzer.label == label) {
      return true;
    }
  }
  return false;
}

void ensureMandatoryRecoveryAnalyzersRegistered(
    const std::vector<RecoveryAnalyzerRef>& analyzers) {
  static constexpr std::array<std::string_view, 2> kMandatoryAnalyzers = {
      "NTFS", "SigScan"};

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
    slots.push_back({analyzer.label, {}});
  }
  return slots;
}

void runRecoveryStageCollectorsInParallel(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root, const std::shared_ptr<spdlog::logger>& logger,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  struct Task {
    std::size_t index = 0;
    std::future<std::vector<RecoveryEvidence>> future;
  };

  std::vector<Task> tasks;
  tasks.reserve(analyzers.size());

  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    const IRecoveryAnalyzer* ptr = analyzers[i].analyzer;
    tasks.push_back(
        {i, std::async(std::launch::async,
                       [ptr, &disk_root] { return ptr->collect(disk_root); })});
  }

  for (auto& task : tasks) {
    try {
      per_analyzer[task.index].evidence = task.future.get();
    } catch (const std::exception& e) {
      logger->error("Recovery({}): ошибка этапа", per_analyzer[task.index].label);
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Recovery({}) exception: {}", per_analyzer[task.index].label,
                    e.what());
    } catch (...) {
      logger->error("Recovery({}): неизвестная ошибка этапа",
                    per_analyzer[task.index].label);
    }
  }
}

void runRecoveryStageCollectorsSequentially(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    per_analyzer[i].evidence = analyzers[i].analyzer->collect(disk_root);
  }
}

void appendRecoverySummaryItem(std::string& summary, const std::string_view label,
                               const std::size_t evidence_count) {
  if (!summary.empty()) {
    summary += ", ";
  }
  summary += label;
  summary.push_back('=');
  summary += std::to_string(evidence_count);
}

std::string mergeRecoveryEvidenceResults(
    std::vector<RecoveryStageSlot>& per_analyzer,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<RecoveryEvidence>& recovery_evidence) {
  std::string summary;
  summary.reserve(per_analyzer.size() * 24);

  for (auto& slot : per_analyzer) {
    appendRecoverySummaryItem(summary, slot.label, slot.evidence.size());
    mergeRecoveryEvidenceToProcessData(slot.evidence, process_data);
    appendMovedVector(recovery_evidence, slot.evidence);
  }

  return summary;
}

}  // namespace

void WindowsDiskAnalyzer::runRecoveryStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 6/7: recovery-источники (USN/VSS/Hiber/NTFS/Registry)");

  const bool run_parallel = performance_options_.enable_parallel_stages &&
                            performance_options_.max_io_workers > 1;

  constexpr std::size_t kDefaultCandidatesPerSource = 2000;
  recovery_evidence_.reserve(recovery_analyzers_.size() *
                             kDefaultCandidatesPerSource);

  std::vector<RecoveryAnalyzerRef> analyzers;
  analyzers.reserve(recovery_analyzers_.size());
  for (const auto& analyzer : recovery_analyzers_) {
    analyzers.push_back({analyzer.label, analyzer.analyzer.get()});
  }
  ensureMandatoryRecoveryAnalyzersRegistered(analyzers);

  auto per_analyzer = createRecoveryStageSlots(analyzers);

  if (run_parallel) {
    logger->info("Recovery: параллельный режим включен (MaxIOWorkers={})",
                 performance_options_.max_io_workers);
    runRecoveryStageCollectorsInParallel(analyzers, disk_root_, logger,
                                         per_analyzer);
  } else {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    runRecoveryStageCollectorsSequentially(analyzers, disk_root_, per_analyzer);
  }

  const std::string summary = mergeRecoveryEvidenceResults(
      per_analyzer, process_data_, recovery_evidence_);
  logger->info("Этап 6/7 завершен: {}", summary);
}

}  // namespace WindowsDiskAnalysis
