/// @file recovery_contract.hpp
/// @brief Canonical source/recovered_from contract for recovery evidence.

#pragma once

#include <array>
#include <string>
#include <string_view>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis::RecoveryContract {

inline constexpr std::string_view kSourceUSN = "USN";
inline constexpr std::string_view kSourceVSS = "VSS";
inline constexpr std::string_view kSourceHiber = "Hiber";
inline constexpr std::string_view kSourceNTFSMetadata = "NTFSMetadata";
inline constexpr std::string_view kSourceRegistryLog = "RegistryLog";
inline constexpr std::string_view kSourceSignatureScan = "SignatureScan";
inline constexpr std::string_view kSourceTSK = "TSK";

inline constexpr std::array<std::string_view, 7> kCanonicalSources = {
    kSourceUSN,
    kSourceVSS,
    kSourceHiber,
    kSourceNTFSMetadata,
    kSourceRegistryLog,
    kSourceSignatureScan,
    kSourceTSK,
};

/// @brief Returns canonical recovery source for a possibly legacy source pair.
[[nodiscard]] std::string canonicalizeRecoverySource(
    std::string source, std::string recovered_from = {});

/// @brief Returns canonical recovered_from marker for a canonical source.
[[nodiscard]] std::string canonicalizeRecoveredFrom(std::string source,
                                                    std::string recovered_from);

/// @brief Canonicalizes source/recovered_from in-place.
void canonicalizeRecoveryEvidence(RecoveryEvidence& evidence);

/// @brief Canonicalizes source/recovered_from for every element.
void canonicalizeRecoveryEvidence(std::vector<RecoveryEvidence>& evidence);

/// @brief Returns true when @p source is one of `kCanonicalSources`.
[[nodiscard]] bool isCanonicalRecoverySource(std::string_view source);

/// @brief Returns true when recovered_from follows `Source.marker` format.
[[nodiscard]] bool isCanonicalRecoveredFrom(std::string_view source,
                                            std::string_view recovered_from);

}  // namespace WindowsDiskAnalysis::RecoveryContract
