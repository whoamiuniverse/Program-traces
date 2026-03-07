/// @file feature_usage_collector.hpp
/// @brief Коллектор артефактов FeatureUsage.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class FeatureUsageCollector
/// @brief Собирает артефакты FeatureUsage из пользовательских hive.
class FeatureUsageCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
