/// @file timeline_collector.hpp
/// @brief Collector for Windows Timeline (ActivitiesCache.db) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TimelineCollector
/// @brief Collects executable file paths from ActivitiesCache.db (ConnectedDevicesPlatform).
///
/// @details Scans per-user ConnectedDevicesPlatform directories as specified in
/// @c ctx.config.timeline_root_suffix for @c ActivitiesCache.db SQLite files.
/// Skipped entirely when @c ctx.config.enable_timeline is @c false.
class TimelineCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from Windows Timeline database files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
