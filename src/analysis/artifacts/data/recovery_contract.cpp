/// @file recovery_contract.cpp
/// @brief Canonical source/recovered_from normalization for recovery evidence.

#include "analysis/artifacts/data/recovery_contract.hpp"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string>
#include <string_view>

#include "common/utils.hpp"

namespace WindowsDiskAnalysis::RecoveryContract {
namespace {

constexpr std::string_view kUnknownMarker = "unknown";

std::string normalizeMarkerToken(std::string token) {
  trim(token);
  token = to_lower(std::move(token));

  std::string normalized;
  normalized.reserve(token.size());

  bool previous_underscore = false;
  for (const char c : token) {
    const auto ch = static_cast<unsigned char>(c);
    const bool is_alpha_num =
        std::isdigit(ch) != 0 || (ch >= 'a' && ch <= 'z');
    if (is_alpha_num) {
      normalized.push_back(static_cast<char>(ch));
      previous_underscore = false;
      continue;
    }

    if (!previous_underscore) {
      normalized.push_back('_');
      previous_underscore = true;
    }
  }

  while (!normalized.empty() && normalized.front() == '_') {
    normalized.erase(normalized.begin());
  }
  while (!normalized.empty() && normalized.back() == '_') {
    normalized.pop_back();
  }

  if (normalized.empty()) {
    return std::string(kUnknownMarker);
  }
  return normalized;
}

std::string buildRecoveredFrom(std::string_view canonical_source,
                               std::string marker) {
  marker = normalizeMarkerToken(std::move(marker));
  if (marker.empty()) {
    marker = std::string(kUnknownMarker);
  }
  return std::string(canonical_source) + "." + marker;
}

bool containsAny(const std::string& lowered,
                 std::initializer_list<std::string_view> needles) {
  for (const auto needle : needles) {
    if (lowered.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

std::string normalizeLegacyUsnRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) return buildRecoveredFrom(kSourceUSN, "unknown");
  if (lowered == "usn(native)" || lowered == "usn.native") {
    return buildRecoveredFrom(kSourceUSN, "native");
  }
  if (lowered == "usn(binary)" || lowered == "usn.binary") {
    return buildRecoveredFrom(kSourceUSN, "binary");
  }
  if (containsAny(lowered, {"$logfile", "logfile"})) {
    return buildRecoveredFrom(kSourceUSN, "logfile_binary");
  }

  if (lowered.rfind("usn(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(
        kSourceUSN,
        lowered.substr(4, lowered.size() - 5));
  }
  if (lowered.rfind("usn.", 0) == 0) {
    return buildRecoveredFrom(kSourceUSN, lowered.substr(4));
  }
  return buildRecoveredFrom(kSourceUSN, lowered);
}

std::string normalizeLegacyVssRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) return buildRecoveredFrom(kSourceVSS, "unknown");
  if (lowered == "vss(native)" || lowered == "vss.native") {
    return buildRecoveredFrom(kSourceVSS, "native");
  }
  if (lowered == "vss(binary)" || lowered == "vss.binary") {
    return buildRecoveredFrom(kSourceVSS, "binary");
  }
  if (containsAny(lowered, {"snapshot_replay", "snapshot replay"})) {
    return buildRecoveredFrom(kSourceVSS, "snapshot_replay");
  }
  if (containsAny(lowered, {"snapshot_prefetch", "snapshot prefetch"})) {
    return buildRecoveredFrom(kSourceVSS, "snapshot_prefetch");
  }
  if (containsAny(lowered, {"pagefile"})) {
    return buildRecoveredFrom(kSourceVSS, "pagefile_binary");
  }
  if (containsAny(lowered, {"memory"})) {
    return buildRecoveredFrom(kSourceVSS, "memory_dump_binary");
  }
  if (containsAny(lowered, {"unallocated"})) {
    return buildRecoveredFrom(kSourceVSS, "unallocated_binary");
  }

  if (lowered.rfind("vss(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(kSourceVSS,
                              lowered.substr(4, lowered.size() - 5));
  }
  if (lowered.rfind("vss.", 0) == 0) {
    return buildRecoveredFrom(kSourceVSS, lowered.substr(4));
  }
  return buildRecoveredFrom(kSourceVSS, lowered);
}

std::string normalizeLegacyHiberRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) return buildRecoveredFrom(kSourceHiber, "unknown");
  if (lowered == "hiber(native)" || lowered == "hiber.native") {
    return buildRecoveredFrom(kSourceHiber, "native");
  }
  if (lowered == "hiber(binary)" || lowered == "hiber.binary") {
    return buildRecoveredFrom(kSourceHiber, "binary");
  }
  if (lowered == "hiber(eprocess)" || lowered == "hiber.eprocess") {
    return buildRecoveredFrom(kSourceHiber, "eprocess");
  }

  if (lowered.rfind("hiber(", 0) == 0 && lowered.back() == ')') {
    const std::string marker = lowered.substr(6, lowered.size() - 7);
    if (marker.find("endpoint") != std::string::npos) {
      if (marker.find("tcp") != std::string::npos) {
        return buildRecoveredFrom(kSourceHiber, "tcp_endpoint");
      }
      if (marker.find("udp") != std::string::npos) {
        return buildRecoveredFrom(kSourceHiber, "udp_endpoint");
      }
      return buildRecoveredFrom(kSourceHiber, "network_endpoint");
    }
    return buildRecoveredFrom(kSourceHiber, marker);
  }
  if (lowered.rfind("hiber.", 0) == 0) {
    return buildRecoveredFrom(kSourceHiber, lowered.substr(6));
  }
  return buildRecoveredFrom(kSourceHiber, lowered);
}

std::string normalizeLegacyNtfsRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) return buildRecoveredFrom(kSourceNTFSMetadata, "unknown");
  if (lowered == "fsmetadata" || lowered == "ntfsmetadata.structured") {
    return buildRecoveredFrom(kSourceNTFSMetadata, "structured");
  }
  if (containsAny(lowered, {"$mft", "mft_binary", "mft(binary)"})) {
    return buildRecoveredFrom(kSourceNTFSMetadata, "mft_binary");
  }
  if (containsAny(lowered, {"$bitmap", "bitmap_binary", "bitmap(binary)"})) {
    return buildRecoveredFrom(kSourceNTFSMetadata, "bitmap_binary");
  }

  if (lowered.rfind("ntfsmetadata(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(
        kSourceNTFSMetadata,
        lowered.substr(13, lowered.size() - 14));
  }
  if (lowered.rfind("ntfsmetadata.", 0) == 0) {
    return buildRecoveredFrom(kSourceNTFSMetadata, lowered.substr(13));
  }
  return buildRecoveredFrom(kSourceNTFSMetadata, lowered);
}

std::string normalizeLegacyRegistryRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) {
    return buildRecoveredFrom(kSourceRegistryLog, "unknown");
  }
  if (containsAny(lowered, {"hvle_dirty_page", "hvle dirty page"})) {
    return buildRecoveredFrom(kSourceRegistryLog, "hvle_dirty_page");
  }
  if (containsAny(lowered, {"dirty_sector", "dirty sector"})) {
    return buildRecoveredFrom(kSourceRegistryLog, "dirty_sector");
  }
  if (containsAny(lowered, {"blf"})) {
    return buildRecoveredFrom(kSourceRegistryLog, "blf");
  }
  if (containsAny(lowered, {"binary"})) {
    return buildRecoveredFrom(kSourceRegistryLog, "binary");
  }

  if (lowered.rfind("registrylog(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(
        kSourceRegistryLog,
        lowered.substr(12, lowered.size() - 13));
  }
  if (lowered.rfind("registrylog.", 0) == 0) {
    return buildRecoveredFrom(kSourceRegistryLog, lowered.substr(12));
  }
  return buildRecoveredFrom(kSourceRegistryLog, lowered);
}

std::string normalizeLegacySignatureRecoveredFrom(const std::string& lowered) {
  if (lowered.empty() || lowered == "signature") {
    return buildRecoveredFrom(kSourceSignatureScan, "signature");
  }

  if (lowered.rfind("signaturescan(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(
        kSourceSignatureScan,
        lowered.substr(14, lowered.size() - 15));
  }
  if (lowered.rfind("signaturescan.", 0) == 0) {
    return buildRecoveredFrom(kSourceSignatureScan, lowered.substr(14));
  }
  return buildRecoveredFrom(kSourceSignatureScan, lowered);
}

std::string normalizeLegacyTskRecoveredFrom(const std::string& lowered) {
  if (lowered.empty()) return buildRecoveredFrom(kSourceTSK, "unknown");
  if (containsAny(lowered, {"deleted"})) {
    return buildRecoveredFrom(kSourceTSK, "deleted");
  }
  if (containsAny(lowered, {"unallocated"})) {
    return buildRecoveredFrom(kSourceTSK, "unallocated");
  }
  if (containsAny(lowered, {"allocated"})) {
    return buildRecoveredFrom(kSourceTSK, "allocated");
  }

  if (lowered.rfind("tsk(", 0) == 0 && lowered.back() == ')') {
    return buildRecoveredFrom(kSourceTSK, lowered.substr(4, lowered.size() - 5));
  }
  if (lowered.rfind("tsk.", 0) == 0) {
    return buildRecoveredFrom(kSourceTSK, lowered.substr(4));
  }
  return buildRecoveredFrom(kSourceTSK, lowered);
}

}  // namespace

std::string canonicalizeRecoverySource(std::string source,
                                       std::string recovered_from) {
  trim(source);
  trim(recovered_from);

  const std::string source_lower = to_lower(source);
  const std::string recovered_lower = to_lower(recovered_from);

  if (containsAny(source_lower, {"signaturescan"}) ||
      containsAny(recovered_lower, {"signaturescan", "signature"})) {
    return std::string(kSourceSignatureScan);
  }

  if (containsAny(source_lower, {"tsk"}) ||
      containsAny(recovered_lower, {"tsk(" ,"tsk."})) {
    return std::string(kSourceTSK);
  }

  if (containsAny(source_lower, {"ntfsmetadata", "fsmetadata"}) ||
      containsAny(recovered_lower, {"ntfsmetadata", "fsmetadata", "$mft",
                                    "$bitmap", "mft_binary",
                                    "bitmap_binary"})) {
    return std::string(kSourceNTFSMetadata);
  }

  if (containsAny(source_lower, {"registry", "registrylog"}) ||
      containsAny(recovered_lower, {"registrylog", "hvle", "dirty_sector",
                                    "dirty page", "blf"})) {
    return std::string(kSourceRegistryLog);
  }

  if (containsAny(source_lower, {"hiber"}) ||
      containsAny(recovered_lower, {"hiber", "eprocess"})) {
    return std::string(kSourceHiber);
  }

  // "endpoint" in recovered_from only implies Hiber when the source or
  // recovered_from already mentions "hiber" (handled above).  A VSS memory
  // dump can also contain endpoint strings, so we no longer let bare
  // "endpoint" trigger Hiber.

  if (containsAny(source_lower, {"usn", "$logfile", "logfile"}) ||
      containsAny(recovered_lower, {"usn", "$logfile", "logfile"})) {
    return std::string(kSourceUSN);
  }

  if (containsAny(source_lower, {"vss", "pagefile", "memory", "unallocated"}) ||
      containsAny(recovered_lower, {"vss", "snapshot", "pagefile",
                                    "memory", "unallocated"})) {
    return std::string(kSourceVSS);
  }

  if (!source.empty()) {
    return source;
  }
  // Empty source with no recognized keywords — return "Unknown" rather than
  // silently defaulting to USN (which hid bugs in callers).
  return "Unknown";
}

std::string canonicalizeRecoveredFrom(std::string source,
                                      std::string recovered_from) {
  trim(source);
  trim(recovered_from);

  source = canonicalizeRecoverySource(std::move(source), recovered_from);
  const std::string lowered = to_lower(recovered_from);

  if (source == kSourceUSN) {
    return normalizeLegacyUsnRecoveredFrom(lowered);
  }
  if (source == kSourceVSS) {
    return normalizeLegacyVssRecoveredFrom(lowered);
  }
  if (source == kSourceHiber) {
    return normalizeLegacyHiberRecoveredFrom(lowered);
  }
  if (source == kSourceNTFSMetadata) {
    return normalizeLegacyNtfsRecoveredFrom(lowered);
  }
  if (source == kSourceRegistryLog) {
    return normalizeLegacyRegistryRecoveredFrom(lowered);
  }
  if (source == kSourceSignatureScan) {
    return normalizeLegacySignatureRecoveredFrom(lowered);
  }
  if (source == kSourceTSK) {
    return normalizeLegacyTskRecoveredFrom(lowered);
  }

  if (recovered_from.empty()) {
    return source + "." + std::string(kUnknownMarker);
  }

  const std::string prefix = source + ".";
  if (lowered.rfind(to_lower(prefix), 0) == 0) {
    return source + "." + normalizeMarkerToken(recovered_from.substr(prefix.size()));
  }
  return source + "." + normalizeMarkerToken(recovered_from);
}

void canonicalizeRecoveryEvidence(RecoveryEvidence& evidence) {
  evidence.source =
      canonicalizeRecoverySource(std::move(evidence.source), evidence.recovered_from);
  evidence.recovered_from = canonicalizeRecoveredFrom(
      evidence.source, std::move(evidence.recovered_from));
}

void canonicalizeRecoveryEvidence(std::vector<RecoveryEvidence>& evidence) {
  for (auto& entry : evidence) {
    canonicalizeRecoveryEvidence(entry);
  }
}

bool isCanonicalRecoverySource(std::string_view source) {
  for (const auto canonical : kCanonicalSources) {
    if (source == canonical) {
      return true;
    }
  }
  return false;
}

bool isCanonicalRecoveredFrom(const std::string_view source,
                              const std::string_view recovered_from) {
  if (!isCanonicalRecoverySource(source) || recovered_from.empty()) {
    return false;
  }

  const std::string prefix = std::string(source) + ".";
  return recovered_from.rfind(prefix, 0) == 0 &&
         recovered_from.size() > prefix.size();
}

}  // namespace WindowsDiskAnalysis::RecoveryContract
