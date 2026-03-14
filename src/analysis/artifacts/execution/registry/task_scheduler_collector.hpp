/// @file task_scheduler_collector.hpp
/// @brief Collector for Task Scheduler execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TaskSchedulerCollector
/// @brief Collects scheduled task artifacts from the filesystem and the SOFTWARE hive.
///
/// @details Reads XML task definition files from @c ctx.config.task_scheduler_root_path
/// and correlates them with @c TaskCache entries in the SOFTWARE hive to extract
/// executable paths and last-run timestamps.
/// Skipped entirely when @c ctx.config.enable_task_scheduler is @c false.
class TaskSchedulerCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects Task Scheduler execution artifacts.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
