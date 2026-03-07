/// @file task_scheduler_collector.hpp
/// @brief Коллектор артефактов Task Scheduler.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TaskSchedulerCollector
/// @brief Собирает задания планировщика из файловой системы и SOFTWARE hive.
class TaskSchedulerCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
