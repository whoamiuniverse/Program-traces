/// @file ntfs_metadata_analyzer.cpp
/// @brief Реализация recovery-анализатора NTFS-метаданных.

#include "ntfs_metadata_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBFSNTFS) && PROGRAM_TRACES_HAVE_LIBFSNTFS
#include <libfsntfs.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryBufferBinary;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

// ---------------------------------------------------------------------------
// Low-level read helpers
// ---------------------------------------------------------------------------

uint16_t readLeUInt16(const std::vector<uint8_t>& bytes, const std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;
  return static_cast<uint16_t>(static_cast<uint16_t>(bytes[offset]) |
                               static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

uint64_t readLeUInt64(const std::vector<uint8_t>& bytes, const std::size_t offset) {
  if (offset + 8 > bytes.size()) return 0;
  uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i)
    value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
  return value;
}

/// @brief Форматирует смещение в hex.
std::string formatOffsetHex(const std::size_t offset) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::uppercase << offset;
  return stream.str();
}

// ---------------------------------------------------------------------------
// Structured MFT types
// ---------------------------------------------------------------------------

/// @brief Данные одной записи $FILE_NAME из MFT-записи.
struct FileNameInfo {
  std::string  name;         ///< Имя файла, декодированное из UTF-16LE.
  uint64_t     parent_ref;   ///< Ссылка на родительскую директорию (bits[47:0] = record#).
  uint8_t      name_type;    ///< 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS.
  uint64_t     creation;     ///< FILETIME из $FILE_NAME.
};

/// @brief Запись в директорном дереве (для реконструкции путей).
struct MftDirEntry {
  std::string  name;           ///< Предпочтительное имя (Win32 > DOS).
  uint64_t     parent_record;  ///< Bits[47:0] родительской MFT-записи.
};

/// @brief Полная информация о MFT-записи, полученная за первый проход.
struct MftRecordInfo {
  uint64_t                    record_number  = 0;
  std::vector<FileNameInfo>   file_names;
  std::string                 object_id_hex; ///< Hex GUID из $OBJECT_ID (если есть).
  bool                        in_use         = false;
  bool                        is_directory   = false;
  bool                        has_attr_list  = false;  ///< Есть ли $ATTRIBUTE_LIST.
  bool                        has_resident_data = false;
  uint64_t                    si_creation    = 0;
  uint64_t                    fn_creation    = 0;  ///< Из первого $FILE_NAME.
};

// ---------------------------------------------------------------------------
// Name decoding
// ---------------------------------------------------------------------------

/// @brief Декодирует UTF-16LE имя из буфера MFT-записи в UTF-8.
/// @param data  Буфер записи.
/// @param offset Байтовое смещение до первого символа имени.
/// @param char_count Количество символов (не байт).
std::string decodeMftUtf16Name(const std::vector<uint8_t>& data,
                                std::size_t offset,
                                std::size_t char_count) {
  std::string result;
  result.reserve(char_count);
  for (std::size_t i = 0; i < char_count; ++i) {
    const std::size_t pos = offset + i * 2;
    if (pos + 2 > data.size()) break;
    const uint16_t cp = static_cast<uint16_t>(data[pos]) |
                        (static_cast<uint16_t>(data[pos + 1]) << 8);
    if (cp < 0x80) {
      result.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      result.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      result.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      result.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  return result;
}

/// @brief Форматирует 16 байт как GUID-строку вида {XXXXXXXX-XXXX-...}.
std::string formatGuidHex(const std::vector<uint8_t>& data, std::size_t offset) {
  if (offset + 16 > data.size()) return "";
  std::ostringstream ss;
  ss << std::uppercase << std::hex << std::setfill('0');
  // Data1 (LE 4 bytes)
  ss << '{';
  for (int i = 3; i >= 0; --i)
    ss << std::setw(2) << static_cast<int>(data[offset + i]);
  ss << '-';
  // Data2 (LE 2 bytes)
  ss << std::setw(2) << static_cast<int>(data[offset + 5])
     << std::setw(2) << static_cast<int>(data[offset + 4]);
  ss << '-';
  // Data3 (LE 2 bytes)
  ss << std::setw(2) << static_cast<int>(data[offset + 7])
     << std::setw(2) << static_cast<int>(data[offset + 6]);
  ss << '-';
  // Data4 (BE 2 bytes)
  ss << std::setw(2) << static_cast<int>(data[offset + 8])
     << std::setw(2) << static_cast<int>(data[offset + 9]);
  ss << '-';
  // Data4 continued (BE 6 bytes)
  for (int i = 10; i < 16; ++i)
    ss << std::setw(2) << static_cast<int>(data[offset + i]);
  ss << '}';
  return ss.str();
}

/// @brief Проверяет, является ли имя файла исполняемым артефактом.
bool hasExecutableName(const std::string& name) {
  if (name.size() < 4) return false;
  std::string lower;
  lower.reserve(name.size());
  for (char c : name) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (const auto* ext : {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
                           ".js", ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".msc"}) {
    const std::string_view sv(ext);
    if (lower.size() >= sv.size() &&
        lower.compare(lower.size() - sv.size(), sv.size(), sv) == 0)
      return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Attribute iteration
// ---------------------------------------------------------------------------

/// @brief Итерирует resident/non-resident атрибуты MFT-записи.
/// @tparam Callback  Тип: void(uint32_t type, bool non_resident,
///                              std::size_t content_start, uint32_t content_size,
///                              std::size_t attr_offset, uint32_t attr_size)
template <typename Callback>
void iterateMftAttributes(const std::vector<uint8_t>& record, Callback&& cb) {
  if (record.size() < 0x30) return;
  std::size_t attr_off = readLeUInt16(record, 0x14);
  while (attr_off + 8 <= record.size()) {
    const uint32_t type = readLeUInt32(record, attr_off);
    if (type == 0xFFFFFFFFU) break;
    const uint32_t attr_size = readLeUInt32(record, attr_off + 4);
    if (attr_size < 24 || attr_off + attr_size > record.size()) break;

    const bool non_resident = record[attr_off + 8] != 0;
    uint32_t content_size = 0;
    std::size_t content_start = 0;
    if (!non_resident) {
      content_size   = readLeUInt32(record, attr_off + 16);
      const uint16_t content_off = readLeUInt16(record, attr_off + 20);
      content_start  = attr_off + content_off;
      if (content_start + content_size > record.size()) {
        attr_off += attr_size;
        continue;
      }
    }
    cb(type, non_resident, content_start, content_size, attr_off, attr_size);
    attr_off += attr_size;
  }
}

// ---------------------------------------------------------------------------
// Per-record parsers
// ---------------------------------------------------------------------------

/// @brief Извлекает все $FILE_NAME атрибуты (0x30) из MFT-записи.
std::vector<FileNameInfo> parseMftFileNames(const std::vector<uint8_t>& record) {
  std::vector<FileNameInfo> result;
  iterateMftAttributes(record, [&](uint32_t type, bool non_resident,
                                    std::size_t cs, uint32_t csz,
                                    std::size_t /*aoff*/, uint32_t /*asz*/) {
    if (type != 0x30U || non_resident || csz < 66) return;
    // $FILE_NAME layout: parent_ref(8), times(32), sizes(16), flags(4), reparse(4),
    //                    name_len(1), name_type(1), name(name_len*2)
    FileNameInfo fn;
    fn.parent_ref  = readLeUInt64(record, cs)      & 0x0000FFFFFFFFFFFFULL;
    fn.creation    = readLeUInt64(record, cs + 8);
    const uint8_t name_len  = record[cs + 64];
    fn.name_type            = record[cs + 65];
    if (name_len > 0 && cs + 66 + static_cast<std::size_t>(name_len) * 2 <= record.size())
      fn.name = decodeMftUtf16Name(record, cs + 66, name_len);
    result.push_back(std::move(fn));
  });
  return result;
}

/// @brief Извлекает GUID из $OBJECT_ID (0x40).
std::string parseMftObjectId(const std::vector<uint8_t>& record) {
  std::string result;
  iterateMftAttributes(record, [&](uint32_t type, bool non_resident,
                                    std::size_t cs, uint32_t csz,
                                    std::size_t /*aoff*/, uint32_t /*asz*/) {
    if (result.empty() && type == 0x40U && !non_resident && csz >= 16)
      result = formatGuidHex(record, cs);
  });
  return result;
}

/// @brief Проверяет наличие $ATTRIBUTE_LIST (0x20) в MFT-записи.
bool hasMftAttributeList(const std::vector<uint8_t>& record) {
  bool found = false;
  iterateMftAttributes(record, [&](uint32_t type, bool, std::size_t, uint32_t,
                                    std::size_t, uint32_t) {
    if (type == 0x20U) found = true;
  });
  return found;
}

/// @brief Возвращает true, если запись содержит resident $DATA (0x80).
bool hasMftResidentData(const std::vector<uint8_t>& record) {
  bool found = false;
  iterateMftAttributes(record, [&](uint32_t type, bool non_resident, std::size_t,
                                    uint32_t csz, std::size_t, uint32_t) {
    if (type == 0x80U && !non_resident && csz > 0) found = true;
  });
  return found;
}

// ---------------------------------------------------------------------------
// Directory tree building
// ---------------------------------------------------------------------------

/// @brief Строит директорное дерево (MFT# → имя + parent) за один проход по данным.
std::unordered_map<uint64_t, MftDirEntry> buildMftDirTree(
    const std::vector<uint8_t>& data,
    const std::size_t record_size,
    const std::size_t max_records) {
  std::unordered_map<uint64_t, MftDirEntry> tree;
  if (record_size < 256 || data.empty()) return tree;

  std::size_t parsed = 0;
  for (std::size_t off = 0; off + record_size <= data.size() && parsed < max_records;
       off += record_size) {
    if (!(data[off] == 'F' && data[off + 1] == 'I' &&
          data[off + 2] == 'L' && data[off + 3] == 'E'))
      continue;
    ++parsed;

    const uint64_t rec_num = off / record_size;
    const uint16_t flags = readLeUInt16(data, off + 0x16);
    const bool in_use    = (flags & 0x01) != 0;
    const bool is_dir    = (flags & 0x02) != 0;

    // Only directories AND in-use files are needed for path resolution.
    // Files can also be parents (hard links to dirs); include all records.
    std::vector<uint8_t> rec(data.begin() + static_cast<std::ptrdiff_t>(off),
                              data.begin() + static_cast<std::ptrdiff_t>(off + record_size));
    const auto fns = parseMftFileNames(rec);
    if (fns.empty()) continue;

    // Prefer Win32 (name_type 1 or 3) over DOS (2) over POSIX (0).
    const FileNameInfo* best = &fns[0];
    for (const auto& fn : fns)
      if (fn.name_type == 1 || fn.name_type == 3) { best = &fn; break; }

    MftDirEntry entry;
    entry.name          = best->name;
    entry.parent_record = best->parent_ref & 0x0000FFFFFFFFFFFFULL;

    (void)in_use; (void)is_dir;
    tree[rec_num] = std::move(entry);
  }
  return tree;
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// @brief Реконструирует полный путь MFT-записи по директорному дереву.
/// @param record_num Номер записи.
/// @param tree       Директорное дерево, построенное buildMftDirTree().
/// @param max_depth  Защита от циклов.
std::string resolveMftPath(
    uint64_t record_num,
    const std::unordered_map<uint64_t, MftDirEntry>& tree,
    int max_depth = 32) {
  std::string path;
  std::unordered_set<uint64_t> visited;
  uint64_t cur = record_num;

  while (max_depth-- > 0 && !visited.count(cur)) {
    visited.insert(cur);
    auto it = tree.find(cur);
    if (it == tree.end()) break;

    const std::string& seg = it->second.name;
    path = path.empty() ? seg : seg + "\\" + path;

    uint64_t parent = it->second.parent_record;
    if (parent == cur || parent == 5) {
      // parent == 5 означает корень тома ($Root)
      path = "\\" + path;
      break;
    }
    cur = parent;
  }
  return path;
}

// ---------------------------------------------------------------------------
// Main fallback parser (two-pass)
// ---------------------------------------------------------------------------

std::vector<RecoveryEvidence> parseMftFallback(
    const fs::path& mft_path,
    const std::size_t max_bytes,
    const std::size_t max_candidates,
    const std::size_t record_size,
    const std::size_t max_records) {
  std::vector<RecoveryEvidence> results;
  if (record_size < 256 || max_candidates == 0) return results;

  const auto data_opt = readFilePrefix(mft_path, max_bytes);
  if (!data_opt.has_value() || data_opt->empty()) return results;

  std::error_code ec;
  const std::string file_ts =
      EvidenceUtils::fileTimeToUtcString(fs::last_write_time(mft_path, ec));

  const std::vector<uint8_t>& data = *data_opt;
  std::unordered_set<std::string> dedup;

  // ------------------------------------------------------------------
  // Pass 1: build directory tree for path reconstruction.
  // ------------------------------------------------------------------
  const auto dir_tree = buildMftDirTree(data, record_size, max_records);

  // ------------------------------------------------------------------
  // Pass 2: structured evidence + binary-scan evidence per record.
  // ------------------------------------------------------------------
  std::size_t parsed_records = 0;

  for (std::size_t offset = 0;
       offset + record_size <= data.size() && parsed_records < max_records &&
       results.size() < max_candidates;
       offset += record_size) {
    if (!(data[offset] == 'F' && data[offset + 1] == 'I' &&
          data[offset + 2] == 'L' && data[offset + 3] == 'E'))
      continue;

    ++parsed_records;

    const uint64_t rec_num = offset / record_size;
    const uint16_t flags   = readLeUInt16(data, offset + 0x16);
    const bool in_use      = (flags & 0x01) != 0;
    const bool is_dir      = (flags & 0x02) != 0;

    std::vector<uint8_t> record(
        data.begin() + static_cast<std::ptrdiff_t>(offset),
        data.begin() + static_cast<std::ptrdiff_t>(offset + record_size));

    // ---- Structured: $FILE_NAME ----------------------------------------
    const auto fns = parseMftFileNames(record);
    if (!fns.empty() && !is_dir) {
      // Use the best name for the executable check.
      const FileNameInfo* best = &fns[0];
      for (const auto& fn : fns)
        if (fn.name_type == 1 || fn.name_type == 3) { best = &fn; break; }

      if (hasExecutableName(best->name)) {
        const std::string full_path = resolveMftPath(rec_num, dir_tree);
        const std::string display   = full_path.empty() ? best->name : full_path;

        // Collect all aliases (short + long names).
        std::ostringstream names_ss;
        for (std::size_t i = 0; i < fns.size(); ++i) {
          if (i) names_ss << "|";
          names_ss << fns[i].name
                   << "(type=" << static_cast<int>(fns[i].name_type) << ")";
        }

        // ---- $OBJECT_ID -----------------------------------------------
        const std::string obj_id = parseMftObjectId(record);

        // ---- $ATTRIBUTE_LIST detection --------------------------------
        const bool has_al  = hasMftAttributeList(record);
        const bool has_rd  = hasMftResidentData(record);

        std::ostringstream details;
        details << "record=" << formatOffsetHex(offset)
                << " rec_num=" << rec_num
                << " flags=" << (in_use ? "in_use" : "deleted")
                << " names=[" << names_ss.str() << "]";
        if (!obj_id.empty())  details << " object_id=" << obj_id;
        if (has_al)           details << " attr_list=true";
        if (has_rd)           details << " resident_data=true";

        RecoveryEvidence ev;
        ev.executable_path = display;
        ev.source          = "NTFSMetadata";
        ev.recovered_from  = "FSMetadata";
        ev.timestamp       = file_ts;
        ev.details         = "artifact=$MFT(structured), " + details.str();

        const std::string key = ev.executable_path + "|" + ev.recovered_from;
        if (dedup.insert(key).second)
          results.push_back(std::move(ev));
      }
    }

    // ---- Binary scan (keeps finding paths embedded as plain strings) ---
    if (results.size() < max_candidates) {
      auto bin_ev = scanRecoveryBufferBinary(
          record, "NTFSMetadata", "$MFT(binary)",
          mft_path.filename().string(), file_ts,
          max_candidates - results.size(), offset, "mft_record", data.size());

      for (auto& ev : bin_ev) {
        std::ostringstream details;
        if (!ev.details.empty()) details << ev.details << ", ";
        details << "record_offset=" << formatOffsetHex(offset)
                << ", flags=" << (in_use ? "in_use" : "deleted");
        if (is_dir)         details << "|directory";
        ev.details = details.str();
      }
      appendUniqueEvidence(results, bin_ev, dedup);
    }
  }

  return results;
}

}  // namespace

// ---------------------------------------------------------------------------
// NTFSMetadataAnalyzer — public API
// ---------------------------------------------------------------------------

NTFSMetadataAnalyzer::NTFSMetadataAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void NTFSMetadataAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      binary_scan_max_mb_ = static_cast<std::size_t>(
          std::max(1, config.getInt("Recovery", "BinaryScanMaxMB",
                                    static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));
      mft_record_size_ = static_cast<std::size_t>(
          std::max(256, config.getInt("Recovery", "MFTRecordSize",
                                      static_cast<int>(mft_record_size_))));
      mft_max_records_ = static_cast<std::size_t>(
          std::max(1000, config.getInt("Recovery", "MFTMaxRecords",
                                       static_cast<int>(mft_max_records_))));
      mft_path_    = config.getString("Recovery", "MFTPath",    mft_path_);
      bitmap_path_ = config.getString("Recovery", "BitmapPath", bitmap_path_);

      for (const std::string& key :
           {"EnableNTFSMetadata", "EnableNativeFsntfsParser",
            "FsntfsFallbackToBinaryOnNativeFailure"}) {
        if (config.hasKey("Recovery", key)) {
          logger->warn(
              "Параметр [Recovery]/{} игнорируется: модуль NTFS всегда активен",
              key);
        }
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки NTFSMetadataAnalyzer");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Ошибка чтения [Recovery] для NTFSMetadata: {}", e.what());
  }
}

std::vector<RecoveryEvidence> NTFSMetadataAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::size_t native_count = 0;
  std::size_t binary_count = 0;

  const fs::path mft_candidate = fs::path(disk_root) / mft_path_;
  if (const auto resolved_mft = findPathCaseInsensitive(mft_candidate);
      resolved_mft.has_value()) {
    bool need_binary_fallback = true;
#if defined(PROGRAM_TRACES_HAVE_LIBFSNTFS) && PROGRAM_TRACES_HAVE_LIBFSNTFS
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "NTFSMetadata(native): libfsntfs подключен, но native "
                "парсер пока experimental и использует fallback");
    need_binary_fallback = true;
#else
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "NTFSMetadata(native): libfsntfs недоступен в текущей сборке");
    need_binary_fallback = true;
#endif

    if (need_binary_fallback) {
      auto mft_evidence = parseMftFallback(
          *resolved_mft, max_bytes, max_candidates_per_source_,
          mft_record_size_, mft_max_records_);
      for (auto& evidence : mft_evidence) {
        if (evidence.recovered_from != "FSMetadata") {
          const std::string previous = evidence.recovered_from;
          evidence.recovered_from = "FSMetadata";
          if (!previous.empty()) {
            evidence.details = "artifact=" + previous +
                               (evidence.details.empty() ? "" : ", " + evidence.details);
          }
        }
      }
      binary_count += mft_evidence.size();
      appendUniqueEvidence(results, mft_evidence, dedup);
    } else {
      native_count++;
    }
  }

  const fs::path bitmap_candidate = fs::path(disk_root) / bitmap_path_;
  if (const auto resolved_bitmap = findPathCaseInsensitive(bitmap_candidate);
      resolved_bitmap.has_value()) {
    auto bitmap_evidence = scanRecoveryFileBinary(
        *resolved_bitmap, "NTFSMetadata", "$Bitmap(binary)", max_bytes,
        max_candidates_per_source_);
    for (auto& evidence : bitmap_evidence) {
      const std::string previous = evidence.recovered_from;
      evidence.recovered_from = "FSMetadata";
      if (!previous.empty()) {
        evidence.details = "artifact=" + previous +
                           (evidence.details.empty() ? "" : ", " + evidence.details);
      }
    }
    binary_count += bitmap_evidence.size();
    appendUniqueEvidence(results, bitmap_evidence, dedup);
  }

  logger->info(
      "Recovery(NTFSMetadata $MFT/$Bitmap): native={} binary={} total={}",
      native_count, binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
