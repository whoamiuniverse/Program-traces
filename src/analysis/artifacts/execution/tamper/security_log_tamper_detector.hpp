/// @file security_log_tamper_detector.hpp
/// @brief Tamper detector for the Security Event Log.
#pragma once
#include <string>
#include <vector>
#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class SecurityLogTamperDetector
/// @brief Checks the Security Event Log for log-clearing events (Event ID 1102).
///
/// @details Reads the Security Event Log at @c ctx.config.security_log_path and
/// scans for Event ID 1102 ("The audit log was cleared"). If detected, appends
/// a corresponding tamper flag to @p global_tamper_flags.
/// Skipped entirely when @c ctx.config.enable_security_log_tamper_check is @c false.
class SecurityLogTamperDetector final : public ITamperSignalDetector {
 public:
  /// @brief Detects Security Event Log tampering and appends flags if found.
  /// @param ctx                 Immutable analysis context (paths, config).
  /// @param global_tamper_flags Output vector of global tamper flags (no duplicates).
  void detect(const ExecutionEvidenceContext& ctx,
              std::vector<std::string>& global_tamper_flags) override;
};

}  // namespace WindowsDiskAnalysis
