/// @file network_profiles_collector.hpp
/// @brief Collector for NetworkList profile execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class NetworkProfilesCollector
/// @brief Collects network profile artifacts from the SOFTWARE registry hive.
///
/// @details Reads the @c NetworkList/Profiles and @c NetworkList/Signatures keys
/// as configured in @c ctx.config to produce network context entries.
/// Skipped entirely when @c ctx.config.enable_network_profiles is @c false.
class NetworkProfilesCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects network profile artifacts from the SOFTWARE hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
