/// @file jump_lists_collector.hpp
/// @brief Collector for Jump Lists execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class JumpListsCollector
/// @brief Collects execution artifacts from Jump Lists (AutomaticDestinations and CustomDestinations).
///
/// @details Scans per-user @c AutomaticDestinations and @c CustomDestinations directories
/// as configured in @c ctx.config.
class JumpListsCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from Jump List files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
