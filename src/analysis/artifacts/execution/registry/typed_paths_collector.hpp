/// @file typed_paths_collector.hpp
/// @brief Collector for TypedPaths (Explorer address bar history) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TypedPathsCollector
/// @brief Collects TypedPaths entries from per-user NTUSER.DAT hives.
///
/// @details Reads the Windows Explorer address bar history from the @c TypedPaths
/// registry key as configured in @c ctx.config.typed_paths_key.
/// Skipped entirely when @c ctx.config.enable_typed_paths is @c false.
class TypedPathsCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects TypedPaths execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
