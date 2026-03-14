/// @file wer_reports_collector.hpp
/// @brief Collector for Windows Error Reporting (WER) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WerReportsCollector
/// @brief Collects executable file paths from @c .wer report files.
///
/// @details Scans both the system-wide WER directory (@c ctx.config.wer_programdata_path)
/// and per-user WER directories (@c ctx.config.wer_user_suffix) for @c .wer report files
/// and extracts the faulting executable paths.
/// Skipped entirely when @c ctx.config.enable_wer is @c false.
class WerReportsCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from WER report files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
