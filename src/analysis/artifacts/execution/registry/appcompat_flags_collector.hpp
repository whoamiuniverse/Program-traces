/// @file appcompat_flags_collector.hpp
/// @brief Collector for AppCompatFlags execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class AppCompatFlagsCollector
/// @brief Collects AppCompatFlags entries from the SOFTWARE hive and per-user NTUSER.DAT hives.
///
/// @details Reads both the @c AppCompatFlags/Layers and @c Compatibility Assistant/Store
/// registry keys as configured in @c ctx.config. Skipped entirely when
/// @c ctx.config.enable_appcompat_flags is @c false.
class AppCompatFlagsCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects AppCompatFlags execution artifacts.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
