/// @file shimcache_decoder.cpp
/// @brief Реализация форматного декодера AppCompatCache.

#include "analysis/artifacts/execution/registry/shimcache_decoder.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"

namespace WindowsDiskAnalysis {
namespace {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::toLowerAscii;

std::optional<std::pair<std::size_t, std::string>> findUtf16Executable(
    const std::vector<uint8_t>& bytes, const std::size_t offset,
    const std::size_t end_offset) {
  if (offset >= bytes.size() || offset >= end_offset) {
    return std::nullopt;
  }

  const std::size_t safe_end = std::min(end_offset, bytes.size());
  for (std::size_t index = offset; index + 8 <= safe_end; index += 2) {
    if (bytes[index] == 0 || bytes[index + 1] != 0) {
      continue;
    }

    std::string value;
    std::size_t cursor = index;
    while (cursor + 1 < safe_end) {
      const uint8_t low = bytes[cursor];
      const uint8_t high = bytes[cursor + 1];
      if (high != 0) {
        value.clear();
        break;
      }
      if (low == 0) {
        break;
      }
      if (low < 32 || low > 126) {
        value.clear();
        break;
      }
      value.push_back(static_cast<char>(low));
      cursor += 2;
    }

    trim(value);
    if (value.empty()) {
      continue;
    }
    std::ranges::replace(value, '/', '\\');
    if (!isLikelyExecutionPath(value, true)) {
      continue;
    }
    if (auto executable = EvidenceUtils::extractExecutableFromCommand(value);
        executable.has_value()) {
      return std::make_pair(index, *executable);
    }
    return std::make_pair(index, value);
  }

  return std::nullopt;
}

uint32_t readLeUInt32Local(const std::vector<uint8_t>& bytes,
                           const std::size_t offset) {
  return EvidenceUtils::readLeUInt32(bytes, offset);
}

void appendRecord(std::vector<ShimCacheRecord>& output,
                  std::unordered_set<std::string>& seen,
                  ShimCacheRecord record) {
  if (record.executable_path.empty()) {
    return;
  }

  const std::string key = toLowerAscii(record.executable_path);
  if (!seen.insert(key).second) {
    return;
  }

  output.push_back(std::move(record));
}

bool readExecutionFlag(const std::vector<uint8_t>& bytes,
                       const std::size_t record_offset,
                       const std::size_t record_size, bool& has_flag,
                       bool& executed) {
  static constexpr std::array<std::size_t, 6> kFlagOffsets = {
      528, 532, 536, 540, 544, 548};

  for (const std::size_t relative_offset : kFlagOffsets) {
    if (relative_offset + 4 > record_size ||
        record_offset + relative_offset + 4 > bytes.size()) {
      continue;
    }

    const uint32_t raw_flag =
        readLeUInt32Local(bytes, record_offset + relative_offset);
    if (raw_flag > 8) {
      continue;
    }

    has_flag = true;
    executed = raw_flag != 0;
    return true;
  }

  return false;
}

std::vector<ShimCacheRecord> parseShimCacheXP(
    const std::vector<uint8_t>& data, const std::size_t max_candidates) {
  std::vector<ShimCacheRecord> results;
  std::unordered_set<std::string> seen;
  static constexpr std::size_t kHeaderSize = 8;
  static constexpr std::size_t kRecordSize = 552;
  static constexpr std::size_t kPathWindow = 528;

  for (std::size_t offset = kHeaderSize;
       offset + kRecordSize <= data.size() && results.size() < max_candidates;
       offset += kRecordSize) {
    const auto path = findUtf16Executable(data, offset, offset + kPathWindow);
    if (!path.has_value()) {
      continue;
    }

    bool has_exec_flag = false;
    bool executed = true;
    readExecutionFlag(data, offset, kRecordSize, has_exec_flag, executed);
    if (has_exec_flag && !executed) {
      continue;
    }

    ShimCacheRecord record;
    record.executable_path = path->second;
    record.timestamp = extractShimCacheTimestamp(
        data, offset, path->first,
        std::min<std::size_t>(kPathWindow, data.size() - path->first));
    record.details = "AppCompatCache(XP32) offset=" + std::to_string(offset);
    appendRecord(results, seen, std::move(record));
  }

  return results;
}

std::vector<ShimCacheRecord> parseShimCacheVista7(
    const std::vector<uint8_t>& data, const std::size_t max_candidates,
    const bool prefer_64bit) {
  std::vector<ShimCacheRecord> results;
  std::unordered_set<std::string> seen;
  std::size_t offset = 8;
  const std::array<std::size_t, 4> entry_sizes = {0, 4, 8, 12};

  while (offset + 16 < data.size() && results.size() < max_candidates) {
    const uint32_t stored_size = readLeUInt32Local(data, offset);
    const std::size_t record_size = stored_size >= 16 && stored_size <= 4096
                                        ? static_cast<std::size_t>(stored_size)
                                        : 0;
    if (record_size == 0 || offset + record_size > data.size()) {
      ++offset;
      continue;
    }

    const std::size_t search_start = offset + (prefer_64bit ? 12 : 8);
    const auto path = findUtf16Executable(
        data, search_start, std::min(offset + record_size, search_start + 512));
    if (!path.has_value()) {
      offset += record_size;
      continue;
    }

    bool has_exec_flag = false;
    bool executed = true;
    for (const std::size_t relative_offset : entry_sizes) {
      if (relative_offset + 4 > record_size) {
        continue;
      }
      const uint32_t candidate_flag =
          readLeUInt32Local(data, offset + record_size - 4 - relative_offset);
      if (candidate_flag <= 8) {
        has_exec_flag = true;
        executed = candidate_flag != 0;
        break;
      }
    }
    if (has_exec_flag && !executed) {
      offset += record_size;
      continue;
    }

    ShimCacheRecord record;
    record.executable_path = path->second;
    record.timestamp = extractShimCacheTimestamp(
        data, offset, path->first,
        std::min<std::size_t>(record_size, data.size() - path->first));
    record.details =
        std::string(prefer_64bit ? "AppCompatCache(Vista7_64)"
                                 : "AppCompatCache(Vista7_32)") +
        " offset=" + std::to_string(offset);
    appendRecord(results, seen, std::move(record));
    offset += record_size;
  }

  return results;
}

std::vector<ShimCacheRecord> parseShimCacheWin8Plus(
    const std::vector<uint8_t>& data, const std::size_t max_candidates) {
  std::vector<ShimCacheRecord> results;
  std::unordered_set<std::string> seen;
  static constexpr std::array<uint8_t, 4> kSignature = {'1', '0', 't', 's'};

  auto it = std::search(data.begin(), data.end(), kSignature.begin(),
                        kSignature.end());
  while (it != data.end() && results.size() < max_candidates) {
    const std::size_t offset =
        static_cast<std::size_t>(std::distance(data.begin(), it));
    const std::size_t search_start = offset + kSignature.size();
    const auto path = findUtf16Executable(
        data, search_start, std::min(data.size(), search_start + 768));
    if (path.has_value()) {
      ShimCacheRecord record;
      record.executable_path = path->second;
      record.timestamp = extractShimCacheTimestamp(
          data, offset, path->first,
          std::min<std::size_t>(768, data.size() - path->first));
      record.details =
          "AppCompatCache(Win8Plus) offset=" + std::to_string(offset);
      record.no_exec_flag = true;
      appendRecord(results, seen, std::move(record));
    }

    it = std::search(std::next(it), data.end(), kSignature.begin(),
                     kSignature.end());
  }

  return results;
}

}  // namespace

ShimCacheFormat detectShimCacheFormat(const std::vector<uint8_t>& data) {
  if (data.size() < 8) {
    return ShimCacheFormat::Unknown;
  }

  const uint32_t signature = readLeUInt32Local(data, 0);
  if (signature == 0x900EF489U) {
    return ShimCacheFormat::XP32;
  }
  if (signature == 0xBADC0FFEU) {
    const auto parsed32 = parseShimCacheVista7(data, 1, false);
    const auto parsed64 = parseShimCacheVista7(data, 1, true);
    if (!parsed64.empty() && parsed32.empty()) {
      return ShimCacheFormat::Vista7_64;
    }
    if (!parsed32.empty() && parsed64.empty()) {
      return ShimCacheFormat::Vista7_32;
    }
    return ShimCacheFormat::Vista7_32;
  }
  if (signature == 0x00000080U || signature == 0x00000030U) {
    return ShimCacheFormat::Win8Plus;
  }

  static constexpr std::array<uint8_t, 4> kWin8Signature = {'1', '0', 't', 's'};
  if (std::search(data.begin(), data.end(), kWin8Signature.begin(),
                  kWin8Signature.end()) != data.end()) {
    return ShimCacheFormat::Win8Plus;
  }

  return ShimCacheFormat::Unknown;
}

std::vector<ShimCacheRecord> parseShimCacheRecords(
    const std::vector<uint8_t>& data, const std::size_t max_candidates) {
  switch (detectShimCacheFormat(data)) {
    case ShimCacheFormat::XP32:
      return parseShimCacheXP(data, max_candidates);
    case ShimCacheFormat::Vista7_32:
      return parseShimCacheVista7(data, max_candidates, false);
    case ShimCacheFormat::Vista7_64:
      return parseShimCacheVista7(data, max_candidates, true);
    case ShimCacheFormat::Win8Plus:
      return parseShimCacheWin8Plus(data, max_candidates);
    case ShimCacheFormat::Unknown:
      return {};
  }

  return {};
}

}  // namespace WindowsDiskAnalysis
