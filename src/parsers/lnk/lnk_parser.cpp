/// @file lnk_parser.cpp
/// @brief Реализация минимального структурного парсера Windows Shell Link.

#include "parsers/lnk/lnk_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "common/utils.hpp"

namespace WindowsDiskAnalysis {
namespace {

constexpr std::size_t kShellLinkHeaderSize = 0x4C;
constexpr uint32_t kExpectedHeaderSize = 0x0000004C;
constexpr uint32_t kHasLinkTargetIdList = 0x00000001;
constexpr uint32_t kHasLinkInfo = 0x00000002;
constexpr uint32_t kHasRelativePath = 0x00000008;
constexpr uint32_t kHasWorkingDir = 0x00000010;
constexpr uint32_t kHasArguments = 0x00000020;
constexpr uint32_t kIsUnicode = 0x00000080;
constexpr uint32_t kVolumeIdAndLocalBasePath = 0x00000001;

constexpr uint8_t kExpectedClsid[16] = {0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x46};

uint16_t readLeUInt16(const std::vector<uint8_t>& data,
                      const std::size_t offset) {
  if (offset + 2 > data.size()) {
    return 0;
  }
  return static_cast<uint16_t>(static_cast<uint16_t>(data[offset]) |
                               (static_cast<uint16_t>(data[offset + 1]) << 8));
}

uint32_t readLeUInt32(const std::vector<uint8_t>& data,
                      const std::size_t offset) {
  if (offset + 4 > data.size()) {
    return 0;
  }
  return static_cast<uint32_t>(data[offset]) |
         static_cast<uint32_t>(data[offset + 1]) << 8 |
         static_cast<uint32_t>(data[offset + 2]) << 16 |
         static_cast<uint32_t>(data[offset + 3]) << 24;
}

uint64_t readLeUInt64(const std::vector<uint8_t>& data,
                      const std::size_t offset) {
  if (offset + 8 > data.size()) {
    return 0;
  }

  uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<uint64_t>(data[offset + index]) << (index * 8);
  }
  return value;
}

std::string readAsciiZ(const std::vector<uint8_t>& data,
                       const std::size_t offset) {
  if (offset >= data.size()) {
    return {};
  }

  std::string value;
  for (std::size_t index = offset; index < data.size(); ++index) {
    const char ch = static_cast<char>(data[index]);
    if (ch == '\0') {
      break;
    }
    value.push_back(ch);
  }
  trim(value);
  return value;
}

std::string readUtf16Z(const std::vector<uint8_t>& data,
                       const std::size_t offset) {
  if (offset + 2 > data.size()) {
    return {};
  }

  std::string value;
  for (std::size_t index = offset; index + 1 < data.size(); index += 2) {
    const uint8_t low = data[index];
    const uint8_t high = data[index + 1];
    if (low == 0 && high == 0) {
      break;
    }
    if (high != 0) {
      break;
    }
    value.push_back(static_cast<char>(low));
  }
  trim(value);
  return value;
}

std::string readSizedString(const std::vector<uint8_t>& data,
                            std::size_t& cursor, const bool is_unicode) {
  if (cursor + 2 > data.size()) {
    cursor = data.size();
    return {};
  }

  const uint16_t char_count = readLeUInt16(data, cursor);
  cursor += 2;
  if (char_count == 0) {
    return {};
  }

  if (is_unicode) {
    const std::size_t byte_count = static_cast<std::size_t>(char_count) * 2;
    if (cursor + byte_count > data.size()) {
      cursor = data.size();
      return {};
    }

    std::string value;
    value.reserve(char_count);
    for (std::size_t index = cursor; index + 1 < cursor + byte_count;
         index += 2) {
      if (data[index] == 0 && data[index + 1] == 0) {
        break;
      }
      if (data[index + 1] != 0) {
        return {};
      }
      value.push_back(static_cast<char>(data[index]));
    }
    cursor += byte_count;
    trim(value);
    return value;
  }

  if (cursor + char_count > data.size()) {
    cursor = data.size();
    return {};
  }
  std::string value(reinterpret_cast<const char*>(data.data() + cursor),
                    reinterpret_cast<const char*>(data.data() + cursor + char_count));
  cursor += char_count;
  trim(value);
  return value;
}

std::string normalizePath(std::string path) {
  trim(path);
  std::ranges::replace(path, '/', '\\');
  return path;
}

std::string joinPathIfNeeded(const std::string& base,
                             const std::string& suffix) {
  if (base.empty()) {
    return normalizePath(suffix);
  }
  if (suffix.empty()) {
    return normalizePath(base);
  }

  std::string normalized_base = normalizePath(base);
  std::string normalized_suffix = normalizePath(suffix);
  const std::string lowered_base = to_lower(normalized_base);
  const std::string lowered_suffix = to_lower(normalized_suffix);
  if (!lowered_suffix.empty() &&
      lowered_base.size() >= lowered_suffix.size() &&
      lowered_base.rfind(lowered_suffix) ==
          lowered_base.size() - lowered_suffix.size()) {
    return normalized_base;
  }

  if (!normalized_base.empty() &&
      normalized_base.back() != '\\' && normalized_base.back() != '/') {
    normalized_base.push_back('\\');
  }
  normalized_base += normalized_suffix;
  return normalized_base;
}

std::optional<std::vector<uint8_t>> readBinaryFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  if (size <= 0) {
    return std::nullopt;
  }
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(static_cast<std::size_t>(size));
  if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
    return std::nullopt;
  }

  return data;
}

}  // namespace

std::optional<LnkInfo> parseLnkFile(const std::string& path) {
  const auto data = readBinaryFile(path);
  if (!data.has_value()) {
    return std::nullopt;
  }
  return parseLnkBytes(*data);
}

std::optional<LnkInfo> parseLnkBytes(const std::vector<uint8_t>& data) {
  if (data.size() < kShellLinkHeaderSize) {
    return std::nullopt;
  }
  if (readLeUInt32(data, 0) != kExpectedHeaderSize) {
    return std::nullopt;
  }
  if (!std::equal(std::begin(kExpectedClsid), std::end(kExpectedClsid),
                  data.begin() + 4)) {
    return std::nullopt;
  }

  LnkInfo info;
  const uint32_t link_flags = readLeUInt32(data, 0x14);
  const bool is_unicode = (link_flags & kIsUnicode) != 0;

  const uint64_t creation_filetime = readLeUInt64(data, 0x1C);
  const uint64_t access_filetime = readLeUInt64(data, 0x24);
  const uint64_t write_filetime = readLeUInt64(data, 0x2C);
  info.creation_time = filetimeToString(creation_filetime);
  info.access_time = filetimeToString(access_filetime);
  info.write_time = filetimeToString(write_filetime);

  std::size_t cursor = kShellLinkHeaderSize;
  if ((link_flags & kHasLinkTargetIdList) != 0) {
    const uint16_t id_list_size = readLeUInt16(data, cursor);
    cursor += 2 + id_list_size;
    if (cursor > data.size()) {
      return std::nullopt;
    }
  }

  std::string common_path_suffix;
  if ((link_flags & kHasLinkInfo) != 0) {
    if (cursor + 0x1C > data.size()) {
      return std::nullopt;
    }

    const std::size_t link_info_offset = cursor;
    const uint32_t link_info_size = readLeUInt32(data, cursor);
    const uint32_t link_info_header_size = readLeUInt32(data, cursor + 4);
    const uint32_t link_info_flags = readLeUInt32(data, cursor + 8);
    const uint32_t local_base_path_offset = readLeUInt32(data, cursor + 16);
    const uint32_t common_path_suffix_offset = readLeUInt32(data, cursor + 24);
    const uint32_t local_base_path_offset_unicode =
        link_info_header_size >= 0x24 ? readLeUInt32(data, cursor + 28) : 0;
    const uint32_t common_path_suffix_offset_unicode =
        link_info_header_size >= 0x24 ? readLeUInt32(data, cursor + 32) : 0;

    if (link_info_size == 0 || link_info_offset + link_info_size > data.size()) {
      return std::nullopt;
    }

    if ((link_info_flags & kVolumeIdAndLocalBasePath) != 0) {
      if (local_base_path_offset_unicode != 0) {
        info.target_path =
            readUtf16Z(data, link_info_offset + local_base_path_offset_unicode);
      } else if (local_base_path_offset != 0) {
        info.target_path =
            readAsciiZ(data, link_info_offset + local_base_path_offset);
      }
    }

    if (common_path_suffix_offset_unicode != 0) {
      common_path_suffix =
          readUtf16Z(data, link_info_offset + common_path_suffix_offset_unicode);
    } else if (common_path_suffix_offset != 0) {
      common_path_suffix =
          readAsciiZ(data, link_info_offset + common_path_suffix_offset);
    }

    cursor += link_info_size;
  }

  if ((link_flags & kHasRelativePath) != 0) {
    info.relative_path = readSizedString(data, cursor, is_unicode);
  }
  if ((link_flags & kHasWorkingDir) != 0) {
    info.working_dir = readSizedString(data, cursor, is_unicode);
  }
  if ((link_flags & kHasArguments) != 0) {
    info.arguments = readSizedString(data, cursor, is_unicode);
  }

  info.target_path = normalizePath(info.target_path);
  common_path_suffix = normalizePath(common_path_suffix);
  info.relative_path = normalizePath(info.relative_path);
  info.working_dir = normalizePath(info.working_dir);
  trim(info.arguments);

  if (!common_path_suffix.empty()) {
    info.target_path = joinPathIfNeeded(info.target_path, common_path_suffix);
  }
  if (info.target_path.empty() && !info.working_dir.empty() &&
      !info.relative_path.empty()) {
    info.target_path = joinPathIfNeeded(info.working_dir, info.relative_path);
  }
  if (info.target_path.empty()) {
    info.target_path = info.relative_path;
  }

  if (info.target_path.empty() && info.relative_path.empty() &&
      info.working_dir.empty() && info.arguments.empty()) {
    return std::nullopt;
  }

  return info;
}

}  // namespace WindowsDiskAnalysis
