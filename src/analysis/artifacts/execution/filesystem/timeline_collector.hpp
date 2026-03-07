/// @file timeline_collector.hpp
/// @brief Коллектор артефактов Windows Timeline (ActivitiesCache.db).
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TimelineCollector
/// @brief Собирает исполняемые файлы из ActivitiesCache.db (ConnectedDevicesPlatform).
class TimelineCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
