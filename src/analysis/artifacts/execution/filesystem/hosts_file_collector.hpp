/// @file hosts_file_collector.hpp
/// @brief Collector for non-standard entries in the Windows hosts file.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class HostsFileCollector
/// @brief Collects non-default entries from the Windows hosts file.
///
/// @details Reads the hosts file at @c ctx.config.hosts_file_path and records
/// any entries that are not part of the standard localhost configuration.
/// Skipped entirely when @c ctx.config.enable_hosts_file is @c false.
class HostsFileCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects non-standard entries from the Windows hosts file.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
