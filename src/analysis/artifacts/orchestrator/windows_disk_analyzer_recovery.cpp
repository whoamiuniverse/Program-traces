/// @file windows_disk_analyzer_recovery.cpp
/// @brief Recovery-stage реализация WindowsDiskAnalyzer.

#include "windows_disk_analyzer.hpp"

#include <vector>

#include "analysis/artifacts/orchestrator/recovery_stage_runner.hpp"
#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

void WindowsDiskAnalyzer::runRecoveryStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 6/7: recovery-источники (USN/VSS/Hiber/NTFS/Registry)");

  const bool run_parallel = performance_options_.enable_parallel_stages &&
                            performance_options_.max_io_workers > 1;

  constexpr std::size_t kDefaultCandidatesPerSource = 2000;
  recovery_evidence_.reserve(recovery_analyzers_.size() *
                             kDefaultCandidatesPerSource);

  std::vector<Orchestrator::RecoveryStage::RecoveryAnalyzerRef> analyzers;
  analyzers.reserve(recovery_analyzers_.size());
  for (const auto& analyzer : recovery_analyzers_) {
    analyzers.push_back({analyzer.label, analyzer.analyzer.get()});
  }
  Orchestrator::RecoveryStage::ensureMandatoryRecoveryAnalyzersRegistered(
      analyzers);

  auto per_analyzer =
      Orchestrator::RecoveryStage::createRecoveryStageSlots(analyzers);

  if (run_parallel) {
    logger->info("Recovery: параллельный режим включен (MaxIOWorkers={})",
                 performance_options_.max_io_workers);
    Orchestrator::RecoveryStage::runRecoveryStageCollectorsInParallel(
        analyzers, disk_root_, per_analyzer);
  } else {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    Orchestrator::RecoveryStage::runRecoveryStageCollectorsSequentially(
        analyzers, disk_root_, per_analyzer);
  }

  const std::string summary =
      Orchestrator::RecoveryStage::mergeRecoveryEvidenceResults(
          per_analyzer, process_data_, recovery_evidence_);
  logger->info("Этап 6/7 завершен: {}", summary);
}

}  // namespace WindowsDiskAnalysis
