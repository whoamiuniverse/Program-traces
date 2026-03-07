/// @file user_assist_runmru_collector.hpp
/// @brief Коллектор артефактов UserAssist и RunMRU.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class UserAssistRunMruCollector
/// @brief Собирает артефакты UserAssist и RunMRU из пользовательских hive.
class UserAssistRunMruCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
