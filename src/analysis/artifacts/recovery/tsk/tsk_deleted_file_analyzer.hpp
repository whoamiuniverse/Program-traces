/// @file tsk_deleted_file_analyzer.hpp
/// @brief Recovery analyzer that uses The Sleuth Kit to find deleted forensic artifacts.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class TskDeletedFileAnalyzer
/// @brief Recovers deleted forensic artifacts from NTFS volumes using The Sleuth Kit.
///
/// @details Unlike the signature-carving approach (SignatureScanner), this analyzer
/// works at the filesystem level: it walks the MFT via libtsk, identifies deleted
/// files with forensic-relevant extensions (.pf, .evtx, .lnk, .dat, etc.), and
/// reads their content (if clusters are still allocated). The recovered content
/// is then passed to the appropriate parser (libscca, libevtx, etc.) or scanned
/// for executable path strings.
///
/// This analyzer also provides access to NTFS features that the fallback parser
/// cannot handle: $ATTRIBUTE_LIST base-record traversal, non-resident data-run
/// decoding, and alternate data streams.
///
/// Configuration is read from the @c [Recovery] section of the INI file.
class TskDeletedFileAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @param config_path   Path to the INI configuration file.
  /// @param image_path    Path to a raw/E01 disk image. If empty, the analyzer
  ///                      attempts to open @p disk_root as a raw device/image.
  explicit TskDeletedFileAnalyzer(std::string config_path,
                                  std::string image_path = {});

  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  void loadConfiguration();

  std::string config_path_;
  std::string image_path_;
  std::size_t max_candidates_       = 5000;
  std::size_t max_file_read_bytes_  = 16 * 1024 * 1024;  ///< Max bytes to read per deleted file.
  std::size_t max_unalloc_scan_mb_  = 256;                ///< Max MB of unallocated space to scan.
};

}  // namespace WindowsDiskAnalysis
