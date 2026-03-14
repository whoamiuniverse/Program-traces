/// @file windows_search_collector.hpp
/// @brief Collector for Windows Search (Windows.edb / ESE) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WindowsSearchCollector
/// @brief Collects executable file paths from Windows.edb via the native ESE parser or binary fallback.
///
/// @details Reads the Windows Search ESE database at the path specified in
/// @c ctx.config.windows_search_path. Skipped entirely when
/// @c ctx.config.enable_windows_search is @c false.
class WindowsSearchCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from the Windows Search ESE database.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
