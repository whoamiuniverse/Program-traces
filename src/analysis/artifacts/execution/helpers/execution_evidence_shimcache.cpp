/// @file execution_evidence_shimcache.cpp
/// @brief ShimCache-specific helpers for ExecutionEvidenceDetail.

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::readLeUInt32;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;

std::optional<std::string> decodeUtf16PathFromBytes(
    const std::vector<uint8_t>& bytes, const std::size_t offset,
    const std::size_t byte_size) {
  if (byte_size < 8 || byte_size > 4096 || byte_size % 2 != 0 ||
      offset + byte_size > bytes.size()) {
    return std::nullopt;
  }

  std::string value;
  value.reserve(byte_size / 2);
  for (std::size_t index = offset; index + 1 < offset + byte_size; index += 2) {
    const uint8_t low = bytes[index];
    const uint8_t high = bytes[index + 1];
    if (high != 0) {
      return std::nullopt;
    }
    if (low == 0) {
      break;
    }
    if (low < 32 || low > 126) {
      return std::nullopt;
    }
    value.push_back(static_cast<char>(low));
  }

  trim(value);
  if (value.empty()) {
    return std::nullopt;
  }
  std::ranges::replace(value, '/', '\\');

  if (!isLikelyExecutionPath(value, true)) {
    return std::nullopt;
  }
  if (auto executable = extractExecutableFromCommand(value);
      executable.has_value()) {
    return executable;
  }
  return value;
}

std::string extractShimCacheTimestamp(const std::vector<uint8_t>& bytes,
                                      const std::size_t entry_offset,
                                      const std::size_t path_offset,
                                      const std::size_t path_size) {
  const std::array<std::size_t, 5> candidates = {
      path_offset + path_size, path_offset + path_size + 8,
      entry_offset + 8, entry_offset + 16,
      entry_offset > 8 ? entry_offset - 8 : 0};

  for (const std::size_t candidate_offset : candidates) {
    if (candidate_offset + 8 > bytes.size()) {
      continue;
    }
    const uint64_t filetime = readLeUInt64(bytes, candidate_offset);
    const std::string timestamp = formatReasonableFiletime(filetime);
    if (!timestamp.empty() && timestamp != "N/A") {
      return timestamp;
    }
  }

  return {};
}

std::vector<ShimCacheStructuredCandidate> parseShimCacheStructuredCandidates(
    const std::vector<uint8_t>& binary, const std::size_t max_candidates) {
  std::vector<ShimCacheStructuredCandidate> results;
  if (binary.size() < 16 || max_candidates == 0) {
    return results;
  }

  struct Pattern {
    std::size_t length_offset = 0;
    std::size_t length_size = 0;
    std::size_t path_offset = 0;
  };

  const std::array<Pattern, 4> patterns = {{
      {0, 2, 2},
      {4, 2, 6},
      {0, 4, 4},
      {8, 4, 12},
  }};

  std::unordered_set<std::string> seen;
  for (std::size_t offset = 0;
       offset + 12 < binary.size() && results.size() < max_candidates;) {
    bool matched = false;
    for (const Pattern& pattern : patterns) {
      if (offset + pattern.path_offset >= binary.size()) {
        continue;
      }

      std::size_t length = 0;
      if (pattern.length_size == 2) {
        length = readLeUInt16Raw(binary, offset + pattern.length_offset);
      } else if (pattern.length_size == 4) {
        length = static_cast<std::size_t>(
            readLeUInt32(binary, offset + pattern.length_offset));
      } else {
        continue;
      }

      if (length < 8 || length > 4096 || length % 2 != 0) {
        continue;
      }

      const std::size_t path_offset = offset + pattern.path_offset;
      if (path_offset + length > binary.size()) {
        continue;
      }

      auto path_opt = decodeUtf16PathFromBytes(binary, path_offset, length);
      if (!path_opt.has_value()) {
        continue;
      }

      const std::string lowered = toLowerAscii(*path_opt);
      if (!seen.insert(lowered).second) {
        offset = path_offset + length;
        matched = true;
        break;
      }

      ShimCacheStructuredCandidate candidate;
      candidate.executable_path = *path_opt;
      candidate.timestamp =
          extractShimCacheTimestamp(binary, offset, path_offset, length);
      candidate.details = "AppCompatCache(structured) offset=" +
                          std::to_string(offset);
      results.push_back(std::move(candidate));

      offset = path_offset + length;
      matched = true;
      break;
    }

    if (!matched) {
      ++offset;
    }
  }

  return results;
}

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
