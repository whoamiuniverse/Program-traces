/// @file bits_queue_collector.hpp
/// @brief Collector for BITS (Background Intelligent Transfer Service) execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class BitsQueueCollector
/// @brief Collects execution artifacts from the BITS transfer queue (qmgr*.dat).
///
/// @details Scans the BITS queue directory specified in @c ctx.config.bits_downloader_path
/// for @c qmgr*.dat files and extracts executable path candidates.
/// Skipped entirely when @c ctx.config.enable_bits is @c false.
class BitsQueueCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects execution artifacts from BITS queue files.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
