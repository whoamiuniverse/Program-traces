/// @file bam_dam_collector.hpp
/// @brief Collector for BAM/DAM (Background/Desktop Activity Moderator) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class BamDamCollector
/// @brief Collects BAM and DAM execution artifacts from the SYSTEM registry hive.
///
/// @details Reads per-user BAM and DAM sub-keys from the SYSTEM hive, supporting
/// both the modern (@c bam/State/UserSettings) and legacy (@c bam/UserSettings) paths.
class BamDamCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects BAM/DAM execution artifacts from the SYSTEM hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
