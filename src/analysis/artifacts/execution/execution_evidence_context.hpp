/// @file execution_evidence_context.hpp
/// @brief Immutable analysis context passed to each execution artifact collector.
#pragma once

#include <cstddef>
#include <string>

#include "analysis/artifacts/execution/execution_evidence_config.hpp"

namespace WindowsDiskAnalysis {

/// @struct ExecutionEvidenceContext
/// @brief Read-only slice of input data supplied to every collector during analysis.
///
/// @details The context is constructed once by @c ExecutionEvidenceAnalyzer and
/// passed by const reference to each @c IExecutionArtifactCollector::collect()
/// and @c ITamperSignalDetector::detect() call.
struct ExecutionEvidenceContext {
  std::string disk_root;          ///< Root path of the analyzed Windows partition.
  std::string software_hive_path; ///< Resolved absolute path to the SOFTWARE registry hive.
  std::string system_hive_path;   ///< Resolved absolute path to the SYSTEM registry hive.
  bool enable_parallel_user_hives =
      false;  ///< Whether parallel traversal of per-user NTUSER.DAT hives is enabled.
  std::size_t worker_threads = 1;  ///< Upper bound on the number of worker threads available.
  const ExecutionEvidenceConfig& config;  ///< Reference to the loaded analysis configuration.
};

}  // namespace WindowsDiskAnalysis
