/// @file network_profiles_collector.hpp
/// @brief Коллектор артефактов NetworkProfiles.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class NetworkProfilesCollector
/// @brief Собирает артефакты сетевых профилей из SOFTWARE hive.
class NetworkProfilesCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
