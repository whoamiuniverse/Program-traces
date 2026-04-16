/// @file vss_analyzer.hpp
/// @brief Recovery analyzer for Volume Shadow Copies, pagefile, and memory images.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class VSSAnalyzer
/// @brief Extracts executable file candidates from VSS snapshots and volatile sources.
///
/// @details Supports Volume Shadow Copies via native @c libvshadow or binary fallback,
/// as well as scanning @c pagefile.sys, @c swapfile.sys, hibernation files,
/// memory dump images, and external unallocated space images.
/// Configuration is read from the @c [Recovery] section of the INI file.
class VSSAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the VSS/Pagefile/Memory recovery analyzer.
  /// @param config_path Path to the INI configuration file.
  explicit VSSAnalyzer(std::string config_path);

  /// @brief Collects recovery evidence from VSS snapshots and volatile sources.
  /// @param disk_root Root path of the mounted Windows partition.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
 /// @brief Loads analyzer parameters from the @c [Recovery] INI section.
  void loadConfiguration();

  std::string config_path_;  ///< Path to the INI configuration file.
  std::size_t binary_scan_max_mb_ = 64;  ///< Maximum bytes (in MB) for the binary fallback scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Maximum number of candidates extracted per source.
  std::size_t vss_native_max_stores_ =
      32;  ///< Maximum number of VSS snapshot stores for the native parser.
  std::string vss_volume_path_;  ///< Explicit raw/device source path for native VSS.
  std::string unallocated_image_path_;  ///< Path to the external unallocated space image file.
  std::size_t vss_snapshot_replay_max_files_ =
      200;  ///< Maximum number of files processed during VSS snapshot replay.
};

}  // namespace WindowsDiskAnalysis
