/// @file bits_queue_collector.hpp
/// @brief Коллектор артефактов BITS (Background Intelligent Transfer Service).
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class BitsQueueCollector
/// @brief Собирает артефакты из очереди BITS (qmgr*.dat).
class BitsQueueCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
