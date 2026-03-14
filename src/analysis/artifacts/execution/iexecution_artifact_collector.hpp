/// @file iexecution_artifact_collector.hpp
/// @brief Base interface for atomic execution artifact collectors.
#pragma once

#include <string>
#include <unordered_map>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/execution/execution_evidence_context.hpp"

namespace WindowsDiskAnalysis {

/// @class IExecutionArtifactCollector
/// @brief Interface for atomic collectors of a single type of execution artifact.
///
/// @details Each concrete implementation must:
///   - Check its corresponding @c enable_X flag in @c ctx.config at the start of
///     @c collect() and return immediately if disabled.
///   - Create a local @c RegistryAnalysis::RegistryParser instance for registry access.
///   - Hold no mutable state and be safe to reuse across calls.
class IExecutionArtifactCollector {
 public:
  /// @brief Virtual destructor for safe polymorphic deletion.
  virtual ~IExecutionArtifactCollector() = default;

  /// @brief Collects execution artifacts and enriches the process map.
  /// @param ctx          Analysis context containing paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  virtual void collect(const ExecutionEvidenceContext& ctx,
                       std::unordered_map<std::string, ProcessInfo>& process_data) = 0;
};

}  // namespace WindowsDiskAnalysis
