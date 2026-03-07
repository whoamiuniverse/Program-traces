/// @file typed_paths_collector.hpp
/// @brief Коллектор артефактов TypedPaths.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class TypedPathsCollector
/// @brief Собирает TypedPaths из NTUSER.DAT пользователей.
class TypedPathsCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
