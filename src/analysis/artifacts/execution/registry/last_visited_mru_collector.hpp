/// @file last_visited_mru_collector.hpp
/// @brief Коллектор артефактов LastVisitedMRU.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class LastVisitedMruCollector
/// @brief Собирает LastVisitedMRU из NTUSER.DAT пользователей.
class LastVisitedMruCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
