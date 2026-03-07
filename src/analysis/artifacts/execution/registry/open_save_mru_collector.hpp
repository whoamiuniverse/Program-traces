/// @file open_save_mru_collector.hpp
/// @brief Коллектор артефактов OpenSaveMRU.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class OpenSaveMruCollector
/// @brief Собирает OpenSaveMRU из NTUSER.DAT пользователей.
class OpenSaveMruCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
