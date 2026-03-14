/// @file shimcache_collector.hpp
/// @brief Collector for ShimCache (AppCompatCache) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class ShimCacheCollector
/// @brief Collects ShimCache (AppCompatCache) artifacts from the SYSTEM registry hive.
///
/// @details Reads the binary @c AppCompatCache value from the SYSTEM hive as configured
/// in @c ctx.config.shimcache_value_path and decodes it using @c ShimCacheDecoder.
/// Skipped entirely when @c ctx.config.enable_shimcache is @c false.
class ShimCacheCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects ShimCache execution artifacts from the SYSTEM hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
