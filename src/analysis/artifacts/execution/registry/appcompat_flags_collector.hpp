/// @file appcompat_flags_collector.hpp
/// @brief Коллектор артефактов AppCompatFlags.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class AppCompatFlagsCollector
/// @brief Собирает AppCompatFlags из SOFTWARE hive и NTUSER.DAT.
class AppCompatFlagsCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
