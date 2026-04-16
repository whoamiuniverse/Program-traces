/// @file user_assist_runmru_collector.hpp
/// @brief Collector for UserAssist and RunMRU execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class UserAssistRunMruCollector
/// @brief Collects UserAssist and RunMRU execution artifacts from per-user NTUSER.DAT hives.
///
/// @details Reads ROT-13 encoded UserAssist entries from @c ctx.config.userassist_key
/// and plain-text RunMRU entries from @c ctx.config.runmru_key in each user's NTUSER.DAT.
class UserAssistRunMruCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects UserAssist and RunMRU execution artifacts from user hives.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
