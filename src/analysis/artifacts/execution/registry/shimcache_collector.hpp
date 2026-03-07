/// @file shimcache_collector.hpp
/// @brief Коллектор артефактов ShimCache.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class ShimCacheCollector
/// @brief Собирает артефакты ShimCache из SYSTEM hive.
class ShimCacheCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
