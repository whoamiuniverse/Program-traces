/// @file signature_scanner.hpp
/// @brief Recovery analyzer that finds Windows forensic artifacts by binary signature.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class SignatureScanner
/// @brief Scans binary sources for Windows forensic artifact signatures.
///
/// @details Complements the existing string-carving in USN/VSS/Hiber analyzers by
/// searching specifically for known binary headers of forensic artifact formats
/// (Prefetch, EVTX, LNK, Registry hive, ESE/JET, SQLite, PE, OLE2/MSI).
///
/// Targets (in order):
///   1. An explicit disk image provided via @c [Recovery]/SignatureScanPath.
///   2. @c pagefile.sys / @c swapfile.sys on the mounted Windows volume.
///   3. @c hiberfil.sys on the mounted Windows volume.
///
/// Configuration is read from the @c [Recovery] section of the INI file.
class SignatureScanner final : public IRecoveryAnalyzer {
 public:
  /// @brief Constructs the signature scanner.
  /// @param config_path   Path to the INI configuration file.
  /// @param image_path_override  If non-empty, overrides [Recovery]/SignatureScanPath from config.
  explicit SignatureScanner(std::string config_path,
                            std::string image_path_override = {});

  /// @brief Scans binary sources for forensic artifact signatures.
  /// @param disk_root Root path of the mounted Windows partition.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
 void loadConfiguration();

  std::string config_path_;
  bool        enable_entropy_       = false;  ///< Enable Shannon entropy analysis for high-entropy blocks.
  std::string image_path_;                    ///< Optional explicit disk image path.
  std::size_t block_size_           = 65536;  ///< Read block size in bytes (64 KiB).
  std::size_t max_scan_mb_          = 512;    ///< Maximum bytes (MB) per target file.
  std::size_t max_candidates_       = 5000;   ///< Maximum evidence records per scanner run.
};

}  // namespace WindowsDiskAnalysis
