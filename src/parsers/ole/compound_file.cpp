/// @file compound_file.cpp
/// @brief Реализация минимального OLE2 Compound File reader.

#include "parsers/ole/compound_file.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "common/utils.hpp"

namespace WindowsDiskAnalysis::CompoundFile {
namespace {

constexpr std::size_t kHeaderSize = 512;
constexpr uint32_t kFreeSector = 0xFFFFFFFFU;
constexpr uint32_t kEndOfChain = 0xFFFFFFFEU;
constexpr uint32_t kNoStream = 0xFFFFFFFFU;
constexpr uint8_t kStreamObject = 2;
constexpr uint8_t kRootStorageObject = 5;
constexpr uint64_t kCompoundSignature = 0xE11AB1A1E011CFD0ULL;
constexpr std::size_t kDirectoryEntrySize = 128;

struct Header {
  std::size_t sector_size = 512;
  std::size_t mini_sector_size = 64;
  uint32_t first_dir_sector = kEndOfChain;
  uint32_t first_mini_fat_sector = kEndOfChain;
  uint32_t mini_fat_sector_count = 0;
  uint32_t first_difat_sector = kEndOfChain;
  uint32_t difat_sector_count = 0;
  uint32_t mini_stream_cutoff = 4096;
  std::vector<uint32_t> difat;
};

struct DirectoryEntry {
  std::string name;
  uint8_t object_type = 0;
  uint32_t start_sector = kEndOfChain;
  uint64_t stream_size = 0;
};

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

std::size_t sectorOffset(const Header& header, const uint32_t sector_index) {
  return kHeaderSize + static_cast<std::size_t>(sector_index) * header.sector_size;
}

bool isChainTerminator(const uint32_t sector) {
  return sector == kEndOfChain || sector == kFreeSector || sector == kNoStream;
}

std::optional<Header> parseHeader(const std::vector<uint8_t>& data) {
  if (data.size() < kHeaderSize) {
    return std::nullopt;
  }
  if (readLeUInt64(data, 0) != kCompoundSignature) {
    return std::nullopt;
  }

  Header header;
  const uint16_t sector_shift = readLeUInt16(data, 0x1E);
  const uint16_t mini_sector_shift = readLeUInt16(data, 0x20);
  header.sector_size = std::size_t{1} << sector_shift;
  header.mini_sector_size = std::size_t{1} << mini_sector_shift;
  header.first_dir_sector = readLeUInt32(data, 0x30);
  header.mini_stream_cutoff = readLeUInt32(data, 0x38);
  header.first_mini_fat_sector = readLeUInt32(data, 0x3C);
  header.mini_fat_sector_count = readLeUInt32(data, 0x40);
  header.first_difat_sector = readLeUInt32(data, 0x44);
  header.difat_sector_count = readLeUInt32(data, 0x48);

  for (std::size_t index = 0; index < 109; ++index) {
    const uint32_t sector = readLeUInt32(data, 0x4C + index * 4);
    if (!isChainTerminator(sector)) {
      header.difat.push_back(sector);
    }
  }

  uint32_t difat_sector = header.first_difat_sector;
  std::unordered_set<uint32_t> visited;
  while (!isChainTerminator(difat_sector) &&
         visited.insert(difat_sector).second &&
         header.difat_sector_count-- > 0) {
    const std::size_t offset = sectorOffset(header, difat_sector);
    if (offset + header.sector_size > data.size()) {
      return std::nullopt;
    }

    const std::size_t entries_per_sector = header.sector_size / 4 - 1;
    for (std::size_t index = 0; index < entries_per_sector; ++index) {
      const uint32_t sector = readLeUInt32(data, offset + index * 4);
      if (!isChainTerminator(sector)) {
        header.difat.push_back(sector);
      }
    }
    difat_sector = readLeUInt32(data, offset + entries_per_sector * 4);
  }

  return header;
}

std::optional<std::vector<uint32_t>> buildFat(const std::vector<uint8_t>& data,
                                              const Header& header) {
  std::vector<uint32_t> fat;
  for (const uint32_t fat_sector : header.difat) {
    const std::size_t offset = sectorOffset(header, fat_sector);
    if (offset + header.sector_size > data.size()) {
      return std::nullopt;
    }

    const std::size_t entries = header.sector_size / 4;
    fat.reserve(fat.size() + entries);
    for (std::size_t index = 0; index < entries; ++index) {
      fat.push_back(readLeUInt32(data, offset + index * 4));
    }
  }
  return fat;
}

std::optional<std::vector<uint8_t>> readRegularStream(
    const std::vector<uint8_t>& data, const Header& header,
    const std::vector<uint32_t>& fat, const uint32_t start_sector,
    const uint64_t stream_size) {
  if (isChainTerminator(start_sector) || stream_size == 0) {
    return std::vector<uint8_t>{};
  }

  std::vector<uint8_t> stream;
  stream.reserve(static_cast<std::size_t>(stream_size));

  uint32_t sector = start_sector;
  std::unordered_set<uint32_t> visited;
  while (!isChainTerminator(sector) && visited.insert(sector).second) {
    if (sector >= fat.size()) {
      return std::nullopt;
    }

    const std::size_t offset = sectorOffset(header, sector);
    if (offset + header.sector_size > data.size()) {
      return std::nullopt;
    }

    const std::size_t copy_size = std::min<std::size_t>(
        header.sector_size,
        static_cast<std::size_t>(stream_size > stream.size()
                                     ? stream_size - stream.size()
                                     : 0));
    stream.insert(stream.end(), data.begin() + static_cast<std::ptrdiff_t>(offset),
                  data.begin() + static_cast<std::ptrdiff_t>(offset + copy_size));
    if (stream.size() >= stream_size) {
      break;
    }

    sector = fat[sector];
  }

  stream.resize(static_cast<std::size_t>(stream_size));
  return stream;
}

std::optional<std::vector<uint32_t>> buildMiniFat(
    const std::vector<uint8_t>& data, const Header& header,
    const std::vector<uint32_t>& fat) {
  if (isChainTerminator(header.first_mini_fat_sector) ||
      header.mini_fat_sector_count == 0) {
    return std::vector<uint32_t>{};
  }

  auto bytes = readRegularStream(
      data, header, fat, header.first_mini_fat_sector,
      static_cast<uint64_t>(header.mini_fat_sector_count) * header.sector_size);
  if (!bytes.has_value()) {
    return std::nullopt;
  }

  std::vector<uint32_t> mini_fat;
  for (std::size_t offset = 0; offset + 4 <= bytes->size(); offset += 4) {
    mini_fat.push_back(readLeUInt32(*bytes, offset));
  }
  return mini_fat;
}

std::vector<DirectoryEntry> parseDirectoryEntries(
    const std::vector<uint8_t>& bytes) {
  std::vector<DirectoryEntry> entries;
  for (std::size_t offset = 0; offset + kDirectoryEntrySize <= bytes.size();
       offset += kDirectoryEntrySize) {
    const uint16_t name_size = readLeUInt16(bytes, offset + 64);
    const uint8_t object_type = bytes[offset + 66];
    if (name_size < 2 || name_size > 64 || object_type == 0) {
      continue;
    }

    std::string name;
    for (std::size_t index = 0;
         index + 1 < static_cast<std::size_t>(name_size - 2); index += 2) {
      const uint8_t low = bytes[offset + index];
      const uint8_t high = bytes[offset + index + 1];
      if (high != 0) {
        name.clear();
        break;
      }
      name.push_back(static_cast<char>(low));
    }

    trim(name);
    if (name.empty()) {
      continue;
    }

    DirectoryEntry entry;
    entry.name = name;
    entry.object_type = object_type;
    entry.start_sector = readLeUInt32(bytes, offset + 116);
    entry.stream_size = readLeUInt64(bytes, offset + 120);
    entries.push_back(std::move(entry));
  }

  return entries;
}

std::optional<std::vector<uint8_t>> readMiniStream(
    const std::vector<uint8_t>& mini_stream_bytes, const Header& header,
    const std::vector<uint32_t>& mini_fat, const uint32_t start_sector,
    const uint64_t stream_size) {
  if (isChainTerminator(start_sector) || stream_size == 0) {
    return std::vector<uint8_t>{};
  }

  std::vector<uint8_t> stream;
  stream.reserve(static_cast<std::size_t>(stream_size));
  uint32_t sector = start_sector;
  std::unordered_set<uint32_t> visited;
  while (!isChainTerminator(sector) && visited.insert(sector).second) {
    if (sector >= mini_fat.size()) {
      return std::nullopt;
    }

    const std::size_t offset =
        static_cast<std::size_t>(sector) * header.mini_sector_size;
    if (offset + header.mini_sector_size > mini_stream_bytes.size()) {
      return std::nullopt;
    }

    const std::size_t copy_size = std::min<std::size_t>(
        header.mini_sector_size,
        static_cast<std::size_t>(stream_size > stream.size()
                                     ? stream_size - stream.size()
                                     : 0));
    stream.insert(stream.end(),
                  mini_stream_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                  mini_stream_bytes.begin() +
                      static_cast<std::ptrdiff_t>(offset + copy_size));
    if (stream.size() >= stream_size) {
      break;
    }

    sector = mini_fat[sector];
  }

  stream.resize(static_cast<std::size_t>(stream_size));
  return stream;
}

}  // namespace

std::optional<std::vector<Stream>> readStreams(const std::string& path) {
  const auto bytes = readBinaryFile(path);
  if (!bytes.has_value()) {
    return std::nullopt;
  }
  return parseStreams(*bytes);
}

std::optional<std::vector<Stream>> parseStreams(const std::vector<uint8_t>& bytes) {
  const auto header = parseHeader(bytes);
  if (!header.has_value()) {
    return std::nullopt;
  }

  const auto fat = buildFat(bytes, *header);
  if (!fat.has_value()) {
    return std::nullopt;
  }

  auto directory_bytes = readRegularStream(
      bytes, *header, *fat, header->first_dir_sector, bytes.size());
  if (!directory_bytes.has_value()) {
    return std::nullopt;
  }

  const auto directory_entries = parseDirectoryEntries(*directory_bytes);
  if (directory_entries.empty()) {
    return std::nullopt;
  }

  DirectoryEntry root_entry;
  bool found_root = false;
  for (const auto& entry : directory_entries) {
    if (entry.object_type == kRootStorageObject) {
      root_entry = entry;
      found_root = true;
      break;
    }
  }

  std::vector<uint8_t> mini_stream_bytes;
  if (found_root && !isChainTerminator(root_entry.start_sector) &&
      root_entry.stream_size > 0) {
    auto root_stream = readRegularStream(
        bytes, *header, *fat, root_entry.start_sector, root_entry.stream_size);
    if (root_stream.has_value()) {
      mini_stream_bytes = std::move(*root_stream);
    }
  }

  const auto mini_fat = buildMiniFat(bytes, *header, *fat);
  if (!mini_fat.has_value()) {
    return std::nullopt;
  }

  std::vector<Stream> streams;
  for (const auto& entry : directory_entries) {
    if (entry.object_type != kStreamObject || entry.name.empty()) {
      continue;
    }

    std::optional<std::vector<uint8_t>> stream_bytes;
    if (entry.stream_size < header->mini_stream_cutoff &&
        !mini_stream_bytes.empty()) {
      stream_bytes = readMiniStream(mini_stream_bytes, *header, *mini_fat,
                                    entry.start_sector, entry.stream_size);
    } else {
      stream_bytes = readRegularStream(bytes, *header, *fat, entry.start_sector,
                                       entry.stream_size);
    }

    if (!stream_bytes.has_value()) {
      continue;
    }
    streams.push_back({entry.name, std::move(*stream_bytes)});
  }

  return streams;
}

}  // namespace WindowsDiskAnalysis::CompoundFile
