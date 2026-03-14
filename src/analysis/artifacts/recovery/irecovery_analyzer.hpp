/// @file irecovery_analyzer.hpp
/// @brief Base interface for forensic recovery analyzers.

#pragma once

#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @class IRecoveryAnalyzer
/// @brief Interface for analyzers that extract recoverable execution evidence.
///
/// @details Each concrete implementation targets a specific recovery source
/// (e.g., USN journal, Volume Shadow Copies, hibernation file, NTFS metadata).
/// The orchestrator stores them as a heterogeneous @c vector<NamedRecoveryAnalyzer>
/// so new sources can be added without modifying the orchestrator header (OCP/DIP).
class IRecoveryAnalyzer {
 public:
  /// @brief Virtual destructor for safe polymorphic deletion.
  virtual ~IRecoveryAnalyzer() noexcept = default;

  /// @brief Collects recoverable evidence from the mounted disk.
  /// @param disk_root Root path of the mounted Windows partition.
  /// @return Vector of recovered evidence records.
  [[nodiscard]] virtual std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const = 0;
};

}  // namespace WindowsDiskAnalysis
