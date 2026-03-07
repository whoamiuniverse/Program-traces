/// @file muicache_collector.hpp
/// @brief Коллектор артефактов MuiCache.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class MuiCacheCollector
/// @brief Собирает MuiCache-записи из NTUSER.DAT пользователей.
class MuiCacheCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
