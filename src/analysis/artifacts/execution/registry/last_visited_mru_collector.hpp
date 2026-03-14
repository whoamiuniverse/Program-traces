/// @file last_visited_mru_collector.hpp
/// @brief Collector for LastVisitedPidlMRU execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class LastVisitedMruCollector
/// @brief Collects LastVisitedPidlMRU entries from per-user NTUSER.DAT hives.
///
/// @details Reads the @c ComDlg32/LastVisitedPidlMRU registry key from each user's
/// NTUSER.DAT as configured in @c ctx.config.last_visited_mru_key.
/// Binary PIDL values are decoded to extract target executable paths.
/// Skipped entirely when @c ctx.config.enable_last_visited_mru is @c false.
class LastVisitedMruCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects LastVisitedPidlMRU execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
