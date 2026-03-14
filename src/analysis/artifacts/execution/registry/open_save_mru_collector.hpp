/// @file open_save_mru_collector.hpp
/// @brief Collector for OpenSavePidlMRU execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class OpenSaveMruCollector
/// @brief Collects OpenSavePidlMRU entries from per-user NTUSER.DAT hives.
///
/// @details Reads the @c ComDlg32/OpenSavePidlMRU registry key and its per-extension
/// sub-keys from each user's NTUSER.DAT as configured in @c ctx.config.open_save_mru_key.
/// Binary PIDL values are decoded to extract file paths.
/// Skipped entirely when @c ctx.config.enable_open_save_mru is @c false.
class OpenSaveMruCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects OpenSavePidlMRU execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
