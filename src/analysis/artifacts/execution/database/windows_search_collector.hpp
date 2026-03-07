/// @file windows_search_collector.hpp
/// @brief Коллектор артефактов Windows Search (Windows.edb / ESE).
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WindowsSearchCollector
/// @brief Собирает исполняемые файлы из Windows.edb через native ESE или binary fallback.
class WindowsSearchCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
