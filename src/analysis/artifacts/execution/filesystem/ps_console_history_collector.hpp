/// @file ps_console_history_collector.hpp
/// @brief Коллектор истории PowerShell консоли.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class PsConsoleHistoryCollector
/// @brief Собирает исполняемые файлы из PSReadline ConsoleHost_history.txt.
class PsConsoleHistoryCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
