/// @file evidence_utils.hpp
/// @brief Утилиты для извлечения и нормализации доказательств исполнения

#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "common/utils.hpp"

namespace WindowsDiskAnalysis::EvidenceUtils {

inline std::string toLowerAscii(std::string text) {
  std::ranges::transform(text, text.begin(), [](const unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

inline void appendUniqueToken(std::vector<std::string>& target, std::string token) {
  trim(token);
  if (token.empty()) return;

  const std::string lowered = toLowerAscii(token);
  const bool exists = std::ranges::any_of(
      target, [&](const std::string& current) {
        return toLowerAscii(current) == lowered;
      });
  if (!exists) {
    target.push_back(std::move(token));
  }
}

inline bool isTimestampLike(const std::string& value) {
  if (value.size() != 19) return false;
  return std::isdigit(static_cast<unsigned char>(value[0])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[1])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[2])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[3])) != 0 &&
         value[4] == '-' &&
         std::isdigit(static_cast<unsigned char>(value[5])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[6])) != 0 &&
         value[7] == '-' &&
         std::isdigit(static_cast<unsigned char>(value[8])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[9])) != 0 &&
         value[10] == ' ' &&
         std::isdigit(static_cast<unsigned char>(value[11])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[12])) != 0 &&
         value[13] == ':' &&
         std::isdigit(static_cast<unsigned char>(value[14])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[15])) != 0 &&
         value[16] == ':' &&
         std::isdigit(static_cast<unsigned char>(value[17])) != 0 &&
         std::isdigit(static_cast<unsigned char>(value[18])) != 0;
}

inline void updateTimestampMin(std::string& target, const std::string& candidate) {
  if (!isTimestampLike(candidate)) return;
  if (target.empty() || candidate < target) {
    target = candidate;
  }
}

inline void updateTimestampMax(std::string& target, const std::string& candidate) {
  if (!isTimestampLike(candidate)) return;
  if (target.empty() || candidate > target) {
    target = candidate;
  }
}

inline std::optional<std::vector<uint8_t>> readFilePrefix(
    const std::filesystem::path& file_path, std::size_t max_bytes) {
  std::error_code ec;
  if (!std::filesystem::exists(file_path, ec) || ec ||
      !std::filesystem::is_regular_file(file_path, ec) || ec) {
    return std::nullopt;
  }

  std::ifstream stream(file_path, std::ios::binary);
  if (!stream.is_open()) {
    return std::nullopt;
  }

  stream.seekg(0, std::ios::end);
  const std::streamoff file_size = stream.tellg();
  if (file_size <= 0) return std::vector<uint8_t>{};

  const std::size_t limit = std::min<std::size_t>(
      max_bytes, static_cast<std::size_t>(file_size));
  stream.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(limit);
  stream.read(reinterpret_cast<char*>(buffer.data()),
              static_cast<std::streamsize>(limit));

  const std::streamsize read_size = stream.gcount();
  if (read_size <= 0) return std::vector<uint8_t>{};
  buffer.resize(static_cast<std::size_t>(read_size));
  return buffer;
}

inline std::vector<std::string> extractAsciiStrings(const std::vector<uint8_t>& data,
                                                    std::size_t min_len = 8) {
  std::vector<std::string> result;
  std::string current;

  for (const uint8_t byte : data) {
    const char ch = static_cast<char>(byte);
    if (ch >= 32 && ch <= 126) {
      current.push_back(ch);
      continue;
    }

    if (current.size() >= min_len) {
      result.push_back(current);
    }
    current.clear();
  }

  if (current.size() >= min_len) {
    result.push_back(current);
  }

  return result;
}

inline std::vector<std::string> extractUtf16LeStrings(
    const std::vector<uint8_t>& data, std::size_t min_len = 8) {
  std::vector<std::string> result;
  std::string current;

  for (std::size_t i = 0; i + 1 < data.size(); i += 2) {
    const uint8_t low = data[i];
    const uint8_t high = data[i + 1];

    if (high == 0 && low >= 32 && low <= 126) {
      current.push_back(static_cast<char>(low));
      continue;
    }

    if (current.size() >= min_len) {
      result.push_back(current);
    }
    current.clear();
  }

  if (current.size() >= min_len) {
    result.push_back(current);
  }

  return result;
}

inline const std::array<std::string_view, 6>& processExecutableExtensions() {
  static const std::array<std::string_view, 6> kExtensions = {
      ".exe", ".com", ".bat", ".cmd", ".ps1", ".msi"};
  return kExtensions;
}

inline bool hasExecutableExtension(const std::string& text) {
  const std::string lowered = toLowerAscii(text);
  for (const std::string_view ext : processExecutableExtensions()) {
    if (lowered.find(ext) != std::string::npos) return true;
  }
  return false;
}

inline std::string trimExecutableSuffix(std::string text) {
  trim(text);
  if (text.empty()) return {};

  const std::string lowered = toLowerAscii(text);
  std::size_t best_pos = std::string::npos;
  std::size_t best_len = 0;
  for (const std::string_view ext : processExecutableExtensions()) {
    const std::size_t pos = lowered.find(ext);
    if (pos == std::string::npos) continue;
    if (best_pos == std::string::npos || pos < best_pos) {
      best_pos = pos;
      best_len = ext.size();
    }
  }

  if (best_pos != std::string::npos) {
    text = text.substr(0, best_pos + best_len);
  }

  trim(text);
  if (!text.empty() && (text.front() == '"' || text.front() == '\'')) {
    text.erase(text.begin());
  }
  while (!text.empty() &&
         (text.back() == '"' || text.back() == '\'' || std::isspace(
              static_cast<unsigned char>(text.back())) != 0)) {
    text.pop_back();
  }

  std::ranges::replace(text, '/', '\\');
  return text;
}

inline bool looksLikeExecutablePath(const std::string& text) {
  if (text.empty()) return false;
  if (!hasExecutableExtension(text)) return false;

  const std::string lowered = toLowerAscii(text);
  if (lowered.find("http://") != std::string::npos ||
      lowered.find("https://") != std::string::npos) {
    return false;
  }

  const auto has_drive_prefix = [&]() {
    std::size_t pos = 0;
    while (pos < text.size()) {
      const unsigned char ch = static_cast<unsigned char>(text[pos]);
      if (std::isspace(ch) != 0 || text[pos] == '"' || text[pos] == '\'' ||
          text[pos] == '@' || text[pos] == '=') {
        pos++;
        continue;
      }
      break;
    }

    return pos + 2 < text.size() &&
           std::isalpha(static_cast<unsigned char>(text[pos])) != 0 &&
           text[pos + 1] == ':' &&
           (text[pos + 2] == '\\' || text[pos + 2] == '/');
  };

  return has_drive_prefix() ||
         lowered.find("\\device\\harddiskvolume") != std::string::npos ||
         lowered.find("\\windows\\") != std::string::npos ||
         lowered.find("\\program files") != std::string::npos ||
         lowered.find("\\users\\") != std::string::npos;
}

inline std::optional<std::string> extractExecutableFromCommand(
    std::string command) {
  trim(command);
  if (command.empty()) return std::nullopt;

  if (command.front() == '"' || command.front() == '\'') {
    const char quote = command.front();
    if (const std::size_t quote_end = command.find(quote, 1);
        quote_end != std::string::npos) {
      command = command.substr(1, quote_end - 1);
    } else {
      command.erase(command.begin());
    }
  }

  command = trimExecutableSuffix(command);
  if (!looksLikeExecutablePath(command)) {
    return std::nullopt;
  }

  if (command.size() > 520) return std::nullopt;
  return command;
}

inline std::vector<std::string> extractExecutableCandidatesFromStrings(
    const std::vector<std::string>& strings, std::size_t max_candidates = 2000) {
  std::vector<std::string> result;
  std::set<std::string> seen;

  for (const std::string& raw : strings) {
    if (auto candidate = extractExecutableFromCommand(raw);
        candidate.has_value()) {
      const std::string lowered = toLowerAscii(*candidate);
      if (seen.insert(lowered).second) {
        result.push_back(*candidate);
        if (result.size() >= max_candidates) break;
      }
    }
  }

  return result;
}

inline std::vector<std::string> extractExecutableCandidatesFromBinary(
    const std::vector<uint8_t>& data, std::size_t max_candidates = 2000) {
  std::vector<std::string> combined = extractAsciiStrings(data);
  std::vector<std::string> utf16 = extractUtf16LeStrings(data);
  combined.insert(combined.end(), utf16.begin(), utf16.end());
  return extractExecutableCandidatesFromStrings(combined, max_candidates);
}

inline std::string fileTimeToUtcString(
    const std::filesystem::file_time_type& value) {
  using namespace std::chrono;
  const auto system_now = system_clock::now();
  const auto file_now = std::filesystem::file_time_type::clock::now();
  const auto system_time =
      time_point_cast<system_clock::duration>(value - file_now + system_now);

  const std::time_t tt = system_clock::to_time_t(system_time);
  return unixTimeToString(tt);
}

inline uint64_t readLeUInt64(const std::vector<uint8_t>& bytes,
                             const std::size_t offset) {
  if (offset + 8 > bytes.size()) return 0;

  uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
  }
  return value;
}

inline uint32_t readLeUInt32(const std::vector<uint8_t>& bytes,
                             const std::size_t offset) {
  if (offset + 4 > bytes.size()) return 0;

  uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(bytes[offset + i]) << (8 * i);
  }
  return value;
}

}  // namespace WindowsDiskAnalysis::EvidenceUtils
