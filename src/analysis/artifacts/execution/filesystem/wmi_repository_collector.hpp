/// @file wmi_repository_collector.hpp
/// @brief Коллектор артефактов из репозитория WMI.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class WmiRepositoryCollector
/// @brief Собирает исполняемые файлы из WMI repository (objects.data, .map, .btr).
class WmiRepositoryCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
