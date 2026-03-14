/// @file muicache_collector.hpp
/// @brief Collector for MuiCache execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class MuiCacheCollector
/// @brief Collects MuiCache entries from per-user NTUSER.DAT hives.
///
/// @details Reads the @c Software/Classes/Local Settings/MuiCache registry key
/// as configured in @c ctx.config.muicache_key from each user's NTUSER.DAT.
/// Each value name is an executable path; the value data contains the friendly name.
/// Skipped entirely when @c ctx.config.enable_muicache is @c false.
class MuiCacheCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects MuiCache execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
