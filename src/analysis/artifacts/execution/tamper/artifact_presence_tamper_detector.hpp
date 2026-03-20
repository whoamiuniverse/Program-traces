/// @file artifact_presence_tamper_detector.hpp
/// @brief Tamper detector based on presence/absence of key forensic artifact files.
#pragma once

#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class ArtifactPresenceTamperDetector
/// @brief Flags missing forensic artifacts that are present on unmodified systems.
///
/// @details Performs three independent filesystem existence checks:
///  - Amcache.hve absent          → @c amcache_missing
///  - $UsnJrnl:$J absent           → @c usn_journal_disabled
///  - SVI dir exists, no snapshots → @c volume_shadow_copies_deleted
///
/// Skipped entirely when @c ctx.config.enable_artifact_presence_tamper_check is @c false.
class ArtifactPresenceTamperDetector final : public ITamperSignalDetector {
 public:
  void detect(const ExecutionEvidenceContext& ctx,
              std::vector<std::string>& global_tamper_flags) override;
};

}  // namespace WindowsDiskAnalysis
