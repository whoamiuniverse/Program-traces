/// @file recent_apps_collector.hpp
/// @brief Collector for RecentApps execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class RecentAppsCollector
/// @brief Collects RecentApps entries from per-user NTUSER.DAT hives.
///
/// @details Reads the @c Search/RecentApps registry key and its @c RecentItems
/// sub-keys from each user's NTUSER.DAT as configured in @c ctx.config.
/// Skipped entirely when @c ctx.config.enable_recent_apps is @c false.
class RecentAppsCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects RecentApps execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
