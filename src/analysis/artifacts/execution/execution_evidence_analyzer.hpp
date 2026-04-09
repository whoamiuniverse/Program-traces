/// @file execution_evidence_analyzer.hpp
/// @brief Orchestrator for the extended process execution evidence analysis stage.

#pragma once

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/execution/execution_evidence_config.hpp"
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class ExecutionEvidenceAnalyzer
/// @brief Orchestrator that loads configuration, initializes collectors, and runs them.
///
/// @details Manages four groups of @c IExecutionArtifactCollector instances
/// (software registry, system registry, filesystem, and database).
/// Groups can optionally be processed in parallel.
class ExecutionEvidenceAnalyzer {
 public:
  /// @brief Constructs the execution evidence orchestrator.
  /// @param os_version Detected Windows OS version string.
  /// @param ini_path   Path to the INI configuration file.
  ExecutionEvidenceAnalyzer(
      std::string os_version, std::string ini_path);

  /// @brief Enriches the process map with execution sources and timeline entries.
  /// @param disk_root          Root path of the Windows partition.
  /// @param process_data       Aggregated process data map (updated in place).
  /// @param global_tamper_flags Legacy output parameter (unused in production pipeline).
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data,
               std::vector<std::string>& global_tamper_flags);

 private:
  /// @brief Loads settings from the @c [ExecutionArtifacts] INI section.
  void loadConfiguration();

  /// @brief Registers all available execution artifact collectors.
  void initializeCollectors();

  /// @brief Type alias for a group of execution artifact collectors.
  using CollectorGroup = std::vector<std::unique_ptr<IExecutionArtifactCollector>>;

  std::string os_version_;  ///< Detected Windows OS version string.
  std::string ini_path_;    ///< Path to the INI configuration file.
  ExecutionEvidenceConfig config_;  ///< Loaded analysis configuration.
  bool enable_parallel_groups_ = false;  ///< Whether collector groups run in parallel.
  bool enable_parallel_user_hive_analysis_ = false;  ///< Whether per-user hive traversal is parallelized.
  std::size_t worker_threads_ =
      std::max<std::size_t>(1, std::thread::hardware_concurrency());  ///< Number of worker threads.
  CollectorGroup software_collectors_;    ///< Collectors reading from the SOFTWARE hive.
  CollectorGroup system_collectors_;      ///< Collectors reading from the SYSTEM hive.
  CollectorGroup filesystem_collectors_;  ///< Collectors reading from the filesystem.
  CollectorGroup database_collectors_;    ///< Collectors reading from ESE/SQLite databases.
};

}  // namespace WindowsDiskAnalysis
