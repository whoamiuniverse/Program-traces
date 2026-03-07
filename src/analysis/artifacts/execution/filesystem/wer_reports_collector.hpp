/// @file wer_reports_collector.hpp
/// @brief Коллектор отчётов Windows Error Reporting (WER).
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WerReportsCollector
/// @brief Собирает исполняемые файлы из .wer отчётов WER.
class WerReportsCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
