/// @file execution_evidence_parsing.cpp
/// @brief Generic string/binary parsing helpers for ExecutionEvidenceDetail.

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractAsciiStrings;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::extractUtf16LeStrings;
using EvidenceUtils::toLowerAscii;

bool hasExecutionExtension(const std::string& candidate,
                           const bool allow_com_extension) {
  const std::string lowered = toLowerAscii(candidate);
  for (const std::string ext : {".exe", ".bat", ".cmd", ".ps1", ".msi"}) {
    if (lowered.size() >= ext.size() &&
        lowered.rfind(ext) == lowered.size() - ext.size()) {
      return true;
    }
  }
  if (!allow_com_extension) {
    return false;
  }
  return lowered.size() >= 4 && lowered.rfind(".com") == lowered.size() - 4;
}

std::vector<std::string> parseListSetting(std::string raw) {
  trim(raw);
  if (raw.empty()) {
    return {};
  }

  std::vector<std::string> values = split(raw, ',');
  for (std::string& value : values) {
    trim(value);
  }

  values.erase(std::remove_if(values.begin(), values.end(),
                              [](const std::string& value) {
                                return value.empty();
                              }),
               values.end());
  return values;
}

std::string extractTaggedValue(std::string value, const std::string& tag_name) {
  const std::string open_tag = "<" + tag_name + ">";
  const std::string close_tag = "</" + tag_name + ">";

  const std::string lowered = toLowerAscii(value);
  const std::string open_lower = toLowerAscii(open_tag);
  const std::string close_lower = toLowerAscii(close_tag);

  const std::size_t open_pos = lowered.find(open_lower);
  if (open_pos == std::string::npos) {
    return {};
  }

  const std::size_t value_start = open_pos + open_tag.size();
  const std::size_t close_pos = lowered.find(close_lower, value_start);
  if (close_pos == std::string::npos || close_pos <= value_start) {
    return {};
  }

  value = value.substr(value_start, close_pos - value_start);
  trim(value);
  return value;
}

std::optional<std::string> tryExtractExecutableFromDecoratedText(
    std::string text) {
  trim(text);
  if (text.empty()) {
    return std::nullopt;
  }

  for (const std::string tag : {"Command", "ApplicationName", "AppPath",
                                "Path"}) {
    std::string tagged = extractTaggedValue(text, tag);
    if (tagged.empty()) {
      continue;
    }
    if (auto executable = extractExecutableFromCommand(tagged);
        executable.has_value()) {
      return executable;
    }
  }

  const std::string lowered = toLowerAscii(text);
  for (const std::string prefix :
       {"apppath=", "applicationpath=", "commandline=", "path=", "imagepath="}) {
    if (lowered.rfind(prefix, 0) == 0 && text.size() > prefix.size()) {
      std::string candidate = text.substr(prefix.size());
      trim(candidate);
      if (auto executable = extractExecutableFromCommand(candidate);
          executable.has_value()) {
        return executable;
      }
    }
  }

  return extractExecutableFromCommand(text);
}

std::vector<std::string> collectReadableStrings(
    const std::vector<uint8_t>& bytes, const std::size_t min_length) {
  std::vector<std::string> values = extractAsciiStrings(bytes, min_length);
  std::vector<std::string> utf16 = extractUtf16LeStrings(bytes, min_length);
  values.insert(values.end(), utf16.begin(), utf16.end());

  std::vector<std::string> normalized;
  normalized.reserve(values.size());
  for (std::string value : values) {
    value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
    trim(value);
    if (!value.empty()) {
      normalized.push_back(std::move(value));
    }
  }

  std::sort(normalized.begin(), normalized.end());
  normalized.erase(std::unique(normalized.begin(), normalized.end()),
                   normalized.end());
  return normalized;
}

std::string makeRelativePathForDetails(const fs::path& base_root,
                                       const fs::path& file_path) {
  std::error_code ec;
  fs::path relative = fs::relative(file_path, base_root, ec);
  if (ec) {
    relative = file_path.filename();
  }
  return normalizePathSeparators(relative.generic_string());
}

bool containsIgnoreCase(std::string value, const std::string& pattern) {
  value = toLowerAscii(std::move(value));
  return value.find(toLowerAscii(pattern)) != std::string::npos;
}

bool isLikelyExecutionPath(std::string candidate,
                           const bool allow_com_extension) {
  trim(candidate);
  if (candidate.empty()) {
    return false;
  }

  std::ranges::replace(candidate, '/', '\\');
  const std::string lowered = toLowerAscii(candidate);
  if (lowered.find("http://") != std::string::npos ||
      lowered.find("https://") != std::string::npos ||
      lowered.find("ftp://") != std::string::npos) {
    return false;
  }
  if (lowered.rfind("p:\\", 0) == 0) {
    return false;
  }
  if (!hasExecutionExtension(lowered, allow_com_extension)) {
    return false;
  }
  if (lowered.find('\\') == std::string::npos) {
    return false;
  }
  if (!allow_com_extension && lowered.size() >= 4 &&
      lowered.rfind(".com") == lowered.size() - 4) {
    return false;
  }

  return lowered.find("\\windows\\") != std::string::npos ||
         lowered.find("\\program files") != std::string::npos ||
         lowered.find("\\programdata\\") != std::string::npos ||
         lowered.find("\\users\\") != std::string::npos ||
         lowered.find("\\appdata\\") != std::string::npos ||
         lowered.find("\\system32\\") != std::string::npos ||
         lowered.find("\\syswow64\\") != std::string::npos ||
         lowered.find("\\temp\\") != std::string::npos;
}

bool looksLikeSid(std::string value) {
  trim(value);
  if (value.size() < 6) {
    return false;
  }
  if (value.rfind("S-", 0) != 0 && value.rfind("s-", 0) != 0) {
    return false;
  }

  bool has_digit = false;
  for (char ch : value) {
    if (std::isdigit(static_cast<unsigned char>(ch)) != 0) {
      has_digit = true;
      continue;
    }
    if (ch == '-' || ch == 'S' || ch == 's') {
      continue;
    }
    return false;
  }
  return has_digit;
}

std::vector<std::string> extractSidCandidatesFromLine(const std::string& line) {
  std::vector<std::string> sid_candidates;
  std::string token;

  auto flush_token = [&]() {
    trim(token);
    if (looksLikeSid(token)) {
      appendUniqueToken(sid_candidates, token);
    }
    token.clear();
  };

  for (const char ch_raw : line) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    if (std::isalnum(ch) != 0 || ch_raw == '-') {
      token.push_back(ch_raw);
    } else if (!token.empty()) {
      flush_token();
    }
  }
  if (!token.empty()) {
    flush_token();
  }
  return sid_candidates;
}

std::string normalizeFirewallDirection(std::string raw_direction) {
  trim(raw_direction);
  if (raw_direction.empty()) {
    return {};
  }

  const std::string lowered = toLowerAscii(raw_direction);
  if (lowered == "in" || lowered == "inbound") {
    return "inbound";
  }
  if (lowered == "out" || lowered == "outbound") {
    return "outbound";
  }
  return raw_direction;
}

std::string normalizeFirewallAction(std::string raw_action) {
  trim(raw_action);
  if (raw_action.empty()) {
    return {};
  }

  const std::string lowered = toLowerAscii(raw_action);
  if (lowered == "allow" || lowered == "allowed") {
    return "allow";
  }
  if (lowered == "block" || lowered == "deny" || lowered == "denied") {
    return "block";
  }
  return raw_action;
}

std::string normalizeFirewallProtocol(std::string raw_protocol) {
  trim(raw_protocol);
  if (raw_protocol.empty()) {
    return {};
  }

  const std::string lowered = toLowerAscii(raw_protocol);
  if (lowered == "6" || lowered == "tcp") {
    return "TCP";
  }
  if (lowered == "17" || lowered == "udp") {
    return "UDP";
  }
  if (lowered == "1" || lowered == "icmp") {
    return "ICMP";
  }
  if (lowered == "58" || lowered == "icmpv6") {
    return "ICMPv6";
  }
  if (lowered == "256" || lowered == "any") {
    return "ANY";
  }
  return raw_protocol;
}

uint16_t readLeUInt16Raw(const std::vector<uint8_t>& bytes,
                         const std::size_t offset) {
  if (offset + 2 > bytes.size()) {
    return 0;
  }

  uint16_t value = 0;
  value |= static_cast<uint16_t>(bytes[offset]);
  value |= static_cast<uint16_t>(bytes[offset + 1]) << 8;
  return value;
}

std::optional<std::string> parseRegistrySystemTime(
    const std::vector<uint8_t>& binary) {
  if (binary.size() < 16) {
    return std::nullopt;
  }

  const uint16_t year = readLeUInt16Raw(binary, 0);
  const uint16_t month = readLeUInt16Raw(binary, 2);
  const uint16_t day = readLeUInt16Raw(binary, 6);
  const uint16_t hour = readLeUInt16Raw(binary, 8);
  const uint16_t minute = readLeUInt16Raw(binary, 10);
  const uint16_t second = readLeUInt16Raw(binary, 12);

  if (year < 1601 || year > 9999 || month == 0 || month > 12 || day == 0 ||
      day > 31 || hour > 23 || minute > 59 || second > 59) {
    return std::nullopt;
  }

  std::ostringstream stream;
  stream << std::setfill('0') << std::setw(4) << year << "-" << std::setw(2)
         << month << "-" << std::setw(2) << day << " " << std::setw(2) << hour
         << ":" << std::setw(2) << minute << ":" << std::setw(2) << second;
  return stream.str();
}

std::string normalizeNetworkProfileCategory(std::string raw_category) {
  trim(raw_category);
  if (raw_category.empty()) {
    return {};
  }

  uint32_t category = 0;
  if (!tryParseUInt32(raw_category, category)) {
    try {
      const unsigned long parsed = std::stoul(raw_category, nullptr, 0);
      if (parsed > std::numeric_limits<uint32_t>::max()) {
        return raw_category;
      }
      category = static_cast<uint32_t>(parsed);
    } catch (...) {
      return raw_category;
    }
  }

  switch (category) {
    case 0:
      return "Public";
    case 1:
      return "Private";
    case 2:
      return "DomainAuthenticated";
    default:
      return std::to_string(category);
  }
}

std::unordered_map<std::string, std::string> parseFirewallRuleData(
    std::string raw_rule) {
  std::unordered_map<std::string, std::string> fields;
  trim(raw_rule);
  if (raw_rule.empty()) {
    return fields;
  }

  for (std::string token : split(raw_rule, '|')) {
    trim(token);
    if (token.empty()) {
      continue;
    }

    const std::size_t delimiter_pos = token.find('=');
    if (delimiter_pos == std::string::npos || delimiter_pos == 0) {
      continue;
    }

    std::string key = token.substr(0, delimiter_pos);
    std::string value = token.substr(delimiter_pos + 1);
    trim(key);
    trim(value);
    key = toLowerAscii(std::move(key));
    if (!key.empty()) {
      fields[key] = std::move(value);
    }
  }

  return fields;
}

std::string networkContextProcessKey() {
  return "__network_context__";
}

std::string formatReasonableFiletime(const uint64_t filetime) {
  if (filetime < kFiletimeUnixEpoch || filetime > kMaxReasonableFiletime) {
    return {};
  }
  return filetimeToString(filetime);
}

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
