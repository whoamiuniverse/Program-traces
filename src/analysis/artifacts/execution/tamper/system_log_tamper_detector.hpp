/// @file system_log_tamper_detector.hpp
/// @brief Tamper detector for the System Event Log.
#pragma once

#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class SystemLogTamperDetector
/// @brief Checks the System Event Log for log-clearing events (Event ID 104).
///
/// @details Reads the System Event Log at @c ctx.config.system_log_path and
/// scans for Event ID 104 ("The System log file was cleared"). If detected,
/// appends @c system_log_cleared to @p global_tamper_flags.
/// Skipped entirely when @c ctx.config.enable_system_log_tamper_check is @c false.
class SystemLogTamperDetector final : public ITamperSignalDetector {
 public:
  void detect(const ExecutionEvidenceContext& ctx,
              std::vector<std::string>& global_tamper_flags) override;
};

}  // namespace WindowsDiskAnalysis
