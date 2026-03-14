/// @file itamper_signal_detector.hpp
/// @brief ISP interface for global tamper signal detectors.
#pragma once

#include <string>
#include <vector>

#include "analysis/artifacts/execution/execution_evidence_context.hpp"

namespace WindowsDiskAnalysis {

/// @class ITamperSignalDetector
/// @brief Interface for detectors of global artifact tampering signals.
///
/// @details Implementations operate exclusively on the global tamper flags
/// vector and must not modify aggregated process data.
class ITamperSignalDetector {
 public:
  /// @brief Virtual destructor for safe polymorphic deletion.
  virtual ~ITamperSignalDetector() = default;

  /// @brief Detects tampering signals and appends corresponding flags.
  /// @param ctx                 Immutable analysis context (paths, config).
  /// @param global_tamper_flags Output vector of global tamper flags (no duplicates).
  virtual void detect(const ExecutionEvidenceContext& ctx,
                      std::vector<std::string>& global_tamper_flags) = 0;
};

}  // namespace WindowsDiskAnalysis
