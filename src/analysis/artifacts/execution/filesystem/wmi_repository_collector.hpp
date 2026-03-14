/// @file wmi_repository_collector.hpp
/// @brief Collector for WMI Repository execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WmiRepositoryCollector
/// @brief Collects executable file paths from WMI repository files (objects.data, .map, .btr).
///
/// @details Scans the WMI repository directory specified in @c ctx.config.wmi_repository_path
/// for known repository files and extracts executable path candidates via binary scanning.
/// Skipped entirely when @c ctx.config.enable_wmi_repository is @c false.
class WmiRepositoryCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from WMI repository files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
