/// @file usn_analyzer.hpp
/// @brief Recovery analyzer for the NTFS USN Change Journal and $LogFile.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class USNAnalyzer
/// @brief Extracts executable file candidates from the USN Change Journal and $LogFile.
///
/// @details Supports both native parsing via @c libfusn and a binary fallback scan.
/// Configuration is read from the @c [Recovery] section of the INI file.
class USNAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the USN/$LogFile recovery analyzer.
  /// @param config_path Path to the INI configuration file.
  explicit USNAnalyzer(std::string config_path);

  /// @brief Collects recovery evidence from the USN Change Journal and $LogFile.
  /// @param disk_root Root path of the mounted Windows partition.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Loads analyzer parameters from the @c [Recovery] INI section.
  void loadConfiguration();

  std::string config_path_;  ///< Path to the INI configuration file.
  bool enabled_ = true;      ///< Whether USN analysis is enabled.
  bool enable_logfile_ = true;  ///< Whether $LogFile fallback scan is enabled.
  bool enable_native_usn_parser_ = true;  ///< Whether to use the native libfusn parser.
  bool usn_fallback_to_binary_on_native_failure_ =
      true;  ///< Whether to fall back to binary scan when native USN parsing fails.
  std::size_t binary_scan_max_mb_ = 64;  ///< Maximum bytes (in MB) for the binary fallback scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Maximum number of candidates extracted per source.
  std::size_t native_usn_max_records_ =
      200000;  ///< Maximum USN records processed by the native parser.
  std::string usn_journal_path_;  ///< Explicit path to an exported $J journal file.
};

}  // namespace WindowsDiskAnalysis
