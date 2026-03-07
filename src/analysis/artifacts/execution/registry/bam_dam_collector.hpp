/// @file bam_dam_collector.hpp
/// @brief Коллектор артефактов BAM/DAM.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class BamDamCollector
/// @brief Собирает артефакты BAM/DAM из SYSTEM hive.
class BamDamCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
