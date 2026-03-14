/// @file ntfs_metadata_analyzer.hpp
/// @brief Recovery analyzer for NTFS metadata files ($MFT and $Bitmap).

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class NTFSMetadataAnalyzer
/// @brief Detects deleted executable files using NTFS $MFT and $Bitmap metadata.
///
/// @details Supports two scanning strategies:
///  - @c $MFT: FILE record parsing followed by execution candidate extraction;
///  - @c $Bitmap: signature/string-based binary scan.
///
/// The native @c libfsntfs integration is optional. When unavailable or on
/// failure, a configurable binary fallback is used.
/// Configuration is read from the @c [Recovery] section of the INI file.
class NTFSMetadataAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the NTFS metadata analyzer.
  /// @param config_path Path to @c config.ini.
  explicit NTFSMetadataAnalyzer(std::string config_path);

  /// @brief Collects recovery evidence from NTFS metadata files.
  /// @param disk_root Root path of the mounted Windows volume.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Loads analyzer parameters from the @c [Recovery] INI section.
  void loadConfiguration();

  std::string config_path_;  ///< Path to the INI configuration file.
  bool enabled_ = true;      ///< Whether NTFS metadata analysis is enabled.
  bool enable_native_fsntfs_parser_ =
      true;  ///< Whether to use the native libfsntfs parser.
  bool fsntfs_fallback_to_binary_on_native_failure_ =
      true;  ///< Whether to fall back to binary scan when native parsing fails.
  std::size_t binary_scan_max_mb_ = 64;  ///< Byte limit (in MB) for the binary scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Maximum number of extracted candidates per source.
  std::size_t mft_record_size_ = 1024;    ///< Size of each MFT record in bytes (used by the binary fallback).
  std::size_t mft_max_records_ = 200000;  ///< Maximum number of MFT records to analyze.
  std::string mft_path_ = "$MFT";         ///< Path to the $MFT file relative to disk_root.
  std::string bitmap_path_ = "$Bitmap";   ///< Path to the $Bitmap file relative to disk_root.
  bool enable_si_fn_divergence_check_ = true;  ///< Whether to check for $STANDARD_INFORMATION / $FILE_NAME timestamp divergence.
  std::size_t timestamp_divergence_threshold_sec_ = 2;  ///< Minimum divergence in seconds to flag as suspicious.
};

}  // namespace WindowsDiskAnalysis
