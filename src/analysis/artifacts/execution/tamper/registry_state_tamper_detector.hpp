/// @file registry_state_tamper_detector.hpp
/// @brief Tamper detector for registry-controlled forensic artifact settings.
#pragma once

#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class RegistryStateTamperDetector
/// @brief Detects anti-forensics configurations stored in the SYSTEM hive.
///
/// @details Reads two registry values that are commonly manipulated to suppress
/// forensic artifact generation:
///  - @c EnablePrefetcher == 0 → appends @c prefetch_disabled
///  - @c EventLog\Start != 2   → appends @c event_log_service_disabled
///
/// Skipped entirely when @c ctx.config.enable_registry_state_tamper_check is @c false.
class RegistryStateTamperDetector final : public ITamperSignalDetector {
 public:
  void detect(const ExecutionEvidenceContext& ctx,
              std::vector<std::string>& global_tamper_flags) override;
};

}  // namespace WindowsDiskAnalysis
