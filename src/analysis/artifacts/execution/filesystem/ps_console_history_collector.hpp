/// @file ps_console_history_collector.hpp
/// @brief Collector for PowerShell console history artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class PsConsoleHistoryCollector
/// @brief Collects executable file paths from PSReadLine ConsoleHost_history.txt files.
///
/// @details Reads per-user PSReadLine history files at the path suffix specified in
/// @c ctx.config.ps_history_suffix and extracts lines that look like executable invocations.
class PsConsoleHistoryCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from PowerShell console history files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
