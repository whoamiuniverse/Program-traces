/// @file jump_lists_collector.hpp
/// @brief Коллектор артефактов Jump Lists.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class JumpListsCollector
/// @brief Собирает артефакты из Jump Lists (AutomaticDestinations/CustomDestinations).
class JumpListsCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
