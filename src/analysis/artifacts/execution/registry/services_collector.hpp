/// @file services_collector.hpp
/// @brief Collector for Windows Services execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class ServicesCollector
/// @brief Collects Windows Services artifacts from the SYSTEM registry hive.
///
/// @details Reads service entries from @c ctx.config.services_root_path in the SYSTEM hive,
/// extracting @c ImagePath values that reference executable files.
/// Skipped entirely when @c ctx.config.enable_services is @c false.
class ServicesCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects Windows Services execution artifacts from the SYSTEM hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
