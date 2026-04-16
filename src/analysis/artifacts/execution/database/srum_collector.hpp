/// @file srum_collector.hpp
/// @brief Collector for SRUM (System Resource Usage Monitor) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class SrumCollector
/// @brief Collects executable file paths from SRUDB.dat via the native ESE parser or binary fallback.
///
/// @details Reads the SRUM database at the path specified in @c ctx.config.srum_path.
class SrumCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from the SRUM database.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
