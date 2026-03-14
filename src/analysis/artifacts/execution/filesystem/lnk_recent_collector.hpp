/// @file lnk_recent_collector.hpp
/// @brief Collector for LNK shortcut files from user Recent folders.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class LnkRecentCollector
/// @brief Collects execution artifacts from @c .lnk shortcut files in user Recent folders.
///
/// @details Enumerates @c .lnk files from per-user Recent directories as
/// configured in @c ctx.config.recent_lnk_suffix and extracts target paths.
/// Skipped entirely when @c ctx.config.enable_lnk_recent is @c false.
class LnkRecentCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from .lnk files in user Recent folders.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
