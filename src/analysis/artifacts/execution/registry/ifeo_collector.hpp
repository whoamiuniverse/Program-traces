/// @file ifeo_collector.hpp
/// @brief Коллектор артефактов Image File Execution Options (IFEO).
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class IfeoCollector
/// @brief Собирает IFEO-записи из SOFTWARE hive.
class IfeoCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
