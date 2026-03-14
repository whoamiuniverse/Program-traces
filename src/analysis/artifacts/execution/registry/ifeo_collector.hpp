/// @file ifeo_collector.hpp
/// @brief Collector for Image File Execution Options (IFEO) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class IfeoCollector
/// @brief Collects IFEO (Image File Execution Options) entries from the SOFTWARE hive.
///
/// @details Reads both the 64-bit (@c ctx.config.ifeo_root_key) and WoW64
/// (@c ctx.config.ifeo_wow6432_root_key) IFEO registry keys.
/// Skipped entirely when @c ctx.config.enable_ifeo is @c false.
class IfeoCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects IFEO execution artifacts from the SOFTWARE hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
