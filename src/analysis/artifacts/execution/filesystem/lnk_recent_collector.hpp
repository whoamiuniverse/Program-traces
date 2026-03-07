/// @file lnk_recent_collector.hpp
/// @brief Коллектор LNK-файлов из папки Recent.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class LnkRecentCollector
/// @brief Собирает артефакты из .lnk файлов в папке Recent пользователей.
class LnkRecentCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
