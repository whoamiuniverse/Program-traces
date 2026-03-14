/// @file registry_log_analyzer.hpp
/// @brief Recovery analyzer for registry transaction log files (LOG1/LOG2).

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class RegistryLogAnalyzer
/// @brief Extracts execution evidence from registry transaction files.
///
/// @details Scans @c *.LOG1, @c *.LOG2, @c *.regtrans-ms, and @c *.blf files
/// located in the Windows registry hive directory using a binary signature scan.
/// Configuration is read from the @c [Recovery] section of the INI file.
class RegistryLogAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the registry transaction log analyzer.
  /// @param config_path Path to @c config.ini.
  explicit RegistryLogAnalyzer(std::string config_path);

  /// @brief Collects recovery evidence from registry transaction log files.
  /// @param disk_root Root path of the mounted Windows volume.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Loads analyzer parameters from the @c [Recovery] INI section.
  void loadConfiguration();

  std::string config_path_;  ///< Path to the INI configuration file.
  bool enabled_ = true;      ///< Whether registry transaction log analysis is enabled.
  std::size_t binary_scan_max_mb_ = 64;  ///< Byte limit (in MB) for the binary scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Maximum number of extracted candidates per source file.
  std::string registry_config_path_ =
      "Windows/System32/config";  ///< Directory containing hive and log files.
};

}  // namespace WindowsDiskAnalysis
