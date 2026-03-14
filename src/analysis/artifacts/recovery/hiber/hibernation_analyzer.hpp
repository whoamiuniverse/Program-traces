/// @file hibernation_analyzer.hpp
/// @brief Recovery analyzer for the Windows hibernation file (hiberfil.sys).

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class HibernationAnalyzer
/// @brief Extracts execution artifacts from @c hiberfil.sys.
///
/// @details Supports two modes:
///  - Native decompression via @c libhibr (experimental);
///  - Binary fallback using signature/string-based recovery scanning.
///
/// Configuration is read from the @c [Recovery] section of the INI file.
class HibernationAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the hibernation file analyzer.
  /// @param config_path Path to @c config.ini.
  explicit HibernationAnalyzer(std::string config_path);

  /// @brief Collects recovery evidence from @c hiberfil.sys.
  /// @param disk_root Root path of the mounted Windows volume.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Loads analyzer parameters from the @c [Recovery] INI section.
  void loadConfiguration();

  std::string config_path_;  ///< Path to the INI configuration file.
  bool enabled_ = true;      ///< Whether hibernation file analysis is enabled.
  bool enable_native_hiber_parser_ =
      true;  ///< Whether to use @c libhibr for native decompression.
  bool hiber_fallback_to_binary_ =
      true;  ///< Whether to fall back to binary scan when native parsing fails.
  std::size_t hiber_max_pages_ =
      16384;  ///< Maximum number of pages to process in native mode (4 KB per page).
  std::size_t binary_scan_max_mb_ = 64;  ///< Maximum bytes (in MB) read during the fallback scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Maximum number of extracted execution candidates.
  std::string hiber_path_ = "hiberfil.sys";  ///< Path to the hibernation file relative to disk_root.
};

}  // namespace WindowsDiskAnalysis
