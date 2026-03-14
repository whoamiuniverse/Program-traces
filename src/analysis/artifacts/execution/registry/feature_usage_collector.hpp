/// @file feature_usage_collector.hpp
/// @brief Collector for FeatureUsage execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class FeatureUsageCollector
/// @brief Collects FeatureUsage execution artifacts from per-user NTUSER.DAT hives.
///
/// @details Reads the @c AppSwitched, @c ShowJumpView, and @c AppBadgeUpdated
/// FeatureUsage sub-keys as configured in @c ctx.config. Skipped entirely when
/// @c ctx.config.enable_feature_usage is @c false.
class FeatureUsageCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects FeatureUsage execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
