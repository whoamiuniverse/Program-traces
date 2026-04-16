/// @file srum_collector.cpp
/// @brief Реализация SrumCollector.
#include "srum_collector.hpp"

#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
#include <libesedb.h>
#endif

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractAsciiStrings;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::extractUtf16LeStrings;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;

namespace {

std::size_t collectSrumBinaryFallback(
    const fs::path& srum_path,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const ExecutionEvidenceContext& ctx) {
  const std::size_t max_bytes = toByteLimit(ctx.config.binary_scan_max_mb);
  const auto data = readFilePrefix(srum_path, max_bytes);
  if (!data.has_value()) return 0;

  const std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
      *data, ctx.config.max_candidates_per_source);
  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(srum_path, ec));

  for (const auto& executable : candidates) {
    addExecutionEvidence(process_data, executable, "SRUM", timestamp,
                        "sru=SRUDB.dat (binary)");
  }
  return candidates.size();
}

// ---------------------------------------------------------------------------
// ESE/JET B-tree page structured parser (1.4)
// ---------------------------------------------------------------------------
//
// The ESE (Extensible Storage Engine) database format (used by SRUDB.dat) has:
//   - File header at offset 0: 4-byte checksum + 4-byte signature (0xEF CD AB 89)
//   - Page size stored at offset 0xEC in the file header (uint32_t LE)
//   - Each page has a 40-byte header (ESE format ≥ Win Vista):
//       [0..3]   checksum / XOR parity
//       [4..11]  page number / flags  (varies by version; we use heuristics)
//       [16..17] number of entries in tag array (uint16_t LE)  — "cbAvailCommon"
//       [20..21] first free byte offset (uint16_t LE)
//       [22..23] count of tags (uint16_t LE) — "cbPageFlags" in older layout
//       [24..25] page flags (uint16_t LE)
//     Flags: 0x0002 = leaf, 0x0080 = long value, 0x0400 = root
//
//   - Tag array starts at the END of the page and grows backwards.
//     Each tag is 4 bytes: uint16_t tag_offset (from page start), uint16_t tag_size.
//     Tag 0 is the "page header" tag; tags 1..n are data records.
//
//   - Data records are "SRUM record nodes". We try to extract null-terminated
//     ASCII strings and UTF-16LE strings of length ≥ 6 from each record blob.
//
// This is purely heuristic: we do not decode the full ESE on-disk format (which
// requires reverse-engineered column descriptors). The goal is to recover
// executable paths from SRUM tables without libesedb.

namespace ese_detail {

static constexpr uint32_t kEseSignature  = 0x89ABCDEF;  // bytes: EF CD AB 89 LE
static constexpr std::size_t kEseHdrSize = 668;          // minimum ESE file header
static constexpr std::size_t kPageHdrSize = 40;
static constexpr uint16_t kPageFlagLeaf  = 0x0002;
static constexpr uint16_t kPageFlagLongVal = 0x0080;
static constexpr std::size_t kTagBytes   = 4;            // bytes per tag entry

/// Reads a uint16_t LE from data[off].
inline uint16_t u16le(const uint8_t* p, std::size_t off) {
  return static_cast<uint16_t>(p[off]) | (static_cast<uint16_t>(p[off + 1]) << 8);
}

/// Reads a uint32_t LE from data[off].
inline uint32_t u32le(const uint8_t* p, std::size_t off) {
  return static_cast<uint32_t>(p[off])
       | (static_cast<uint32_t>(p[off + 1]) << 8)
       | (static_cast<uint32_t>(p[off + 2]) << 16)
       | (static_cast<uint32_t>(p[off + 3]) << 24);
}

/// Detects ESE signature and returns page size (0 on failure).
std::size_t detectEsePageSize(const std::vector<uint8_t>& data) {
  if (data.size() < kEseHdrSize) return 0;
  const uint32_t sig = u32le(data.data(), 4);
  if (sig != kEseSignature) return 0;
  // Page size is at file offset 0xEC (236 decimal).
  const uint32_t pg = u32le(data.data(), 0xEC);
  if (pg != 4096 && pg != 8192 && pg != 16384 && pg != 32768) return 0;
  return static_cast<std::size_t>(pg);
}

/// Extracts printable ASCII strings of length ≥ min_len from a byte blob.
void extractAsciiFromBlob(const uint8_t* data, std::size_t sz,
                          std::size_t min_len,
                          std::vector<std::string>& out) {
  std::string cur;
  for (std::size_t i = 0; i < sz; ++i) {
    const uint8_t b = data[i];
    if (b >= 0x20 && b < 0x7F) {
      cur.push_back(static_cast<char>(b));
    } else {
      if (cur.size() >= min_len) out.push_back(cur);
      cur.clear();
    }
  }
  if (cur.size() >= min_len) out.push_back(cur);
}

/// Extracts UTF-16LE strings (ASCII code points only) of length ≥ min_len from blob.
void extractUtf16FromBlob(const uint8_t* data, std::size_t sz,
                          std::size_t min_len,
                          std::vector<std::string>& out) {
  if (sz < 2) return;
  std::string cur;
  for (std::size_t i = 0; i + 1 < sz; i += 2) {
    const uint8_t lo = data[i];
    const uint8_t hi = data[i + 1];
    if (hi == 0 && lo >= 0x20 && lo < 0x7F) {
      cur.push_back(static_cast<char>(lo));
    } else if (lo == 0 && hi == 0) {
      if (cur.size() >= min_len) out.push_back(cur);
      cur.clear();
    } else {
      if (cur.size() >= min_len) out.push_back(cur);
      cur.clear();
      // Don't skip — restart scan from next byte boundary.
    }
  }
  if (cur.size() >= min_len) out.push_back(cur);
}

}  // namespace ese_detail

/// @brief Structured ESE B-tree page parser for SRUM (Phase 1.4).
/// Parses the ESE file header, enumerates leaf pages, reads tag arrays,
/// and extracts executable path candidates from record blobs.
std::size_t collectSrumEseStructured(
    const fs::path& srum_path,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const ExecutionEvidenceContext& ctx) {
  using namespace ese_detail;

  // We need a larger read than binary fallback to walk multiple pages.
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 128 * 1024 * 1024);
  const auto data_opt = readFilePrefix(srum_path, max_bytes);
  if (!data_opt.has_value()) return 0;
  const std::vector<uint8_t>& data = *data_opt;

  const std::size_t page_size = detectEsePageSize(data);
  if (page_size == 0) return 0;  // Not an ESE file or format unsupported.

  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(fs::last_write_time(srum_path, ec));

  std::size_t collected = 0;
  std::unordered_set<std::string> seen;

  // ESE pages start after the two shadow-copy header pages (page 0 and 1),
  // i.e., data starts at offset page_size * 2 from file start.
  // We scan from offset page_size (skip file header page) through end of data.
  for (std::size_t page_off = page_size;
       page_off + page_size <= data.size() &&
       collected < ctx.config.max_candidates_per_source;
       page_off += page_size) {

    const uint8_t* pg = data.data() + page_off;

    // Page flags are at byte offset 24 of the page header (ESE format ≥ Vista).
    const uint16_t flags = u16le(pg, 24);
    const bool is_leaf     = (flags & kPageFlagLeaf)    != 0;
    const bool is_longval  = (flags & kPageFlagLongVal) != 0;
    if (!is_leaf || is_longval) continue;  // Only process regular leaf pages.

    // Number of tags is stored as uint16_t at page offset 22.
    const uint16_t tag_count = u16le(pg, 22);
    if (tag_count == 0 || tag_count > 2000) continue;  // Sanity check.

    // Tags grow backwards from the end of the page.
    // Tag[0] is the page header tag; data tags are [1..tag_count-1].
    for (uint16_t t = 1; t < tag_count &&
         collected < ctx.config.max_candidates_per_source; ++t) {
      // Tag t is at page_size - (t+1)*kTagBytes from page start.
      const std::size_t tag_pos = page_size - static_cast<std::size_t>(t + 1) * kTagBytes;
      if (tag_pos + kTagBytes > page_size) break;

      const uint16_t rec_off  = u16le(pg, tag_pos);
      const uint16_t rec_size = u16le(pg, tag_pos + 2);
      // High nibble of rec_size encodes tag flags in some versions; mask it.
      const uint16_t actual_size = rec_size & 0x1FFF;

      if (actual_size == 0) continue;
      if (static_cast<std::size_t>(rec_off) + actual_size > page_size) continue;

      const uint8_t* rec = pg + rec_off;

      // Extract strings from record blob.
      std::vector<std::string> strings;
      extractAsciiFromBlob(rec, actual_size, 6, strings);
      extractUtf16FromBlob(rec, actual_size, 6, strings);

      for (const auto& s : strings) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        std::string exe;
        if (const auto opt = extractExecutableFromCommand(s); opt.has_value()) {
          exe = *opt;
        } else if (isLikelyExecutionPath(s)) {
          exe = s;
        }
        if (exe.empty()) continue;
        if (!seen.insert(exe).second) continue;

        addExecutionEvidence(process_data, exe, "SRUM", timestamp,
                             "sru=SRUDB.dat (ese_structured)"
                             " page=0x" + [&]() {
                               char buf[16];
                               std::snprintf(buf, sizeof(buf), "%zx",
                                             page_off / page_size);
                               return std::string(buf);
                             }());
        ++collected;
      }
    }
  }
  return collected;
}

std::size_t collectSrumNative(
    const fs::path& srum_path,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const ExecutionEvidenceContext& ctx) {
#if !defined(PROGRAM_TRACES_HAVE_LIBESEDB) || !PROGRAM_TRACES_HAVE_LIBESEDB
  static_cast<void>(srum_path);
  static_cast<void>(process_data);
  static_cast<void>(ctx);
  return 0;
#else
  const auto logger = GlobalLogger::get();

  const std::string path_string = srum_path.string();
  if (path_string.empty()) return 0;

  std::unordered_set<std::string> table_allowlist_lower;
  for (std::string table_name : ctx.config.srum_table_allowlist) {
    trim(table_name);
    if (!table_name.empty()) {
      table_allowlist_lower.insert(toLowerAscii(std::move(table_name)));
    }
  }

  auto is_table_allowed = [&](const std::string& table_name) {
    if (table_allowlist_lower.empty()) return true;
    return table_allowlist_lower.contains(toLowerAscii(table_name));
  };

  libesedb_file_t* file = nullptr;
  libesedb_error_t* error = nullptr;

  auto free_error = [&]() {
    if (error != nullptr) {
      libesedb_error_free(&error);
      error = nullptr;
    }
  };
  auto close_file = [&]() {
    if (file != nullptr) {
      libesedb_file_close(file, nullptr);
      libesedb_file_free(&file, nullptr);
      file = nullptr;
    }
  };

  if (libesedb_file_initialize(&file, &error) != 1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "SRUM(native): не удалось инициализировать libesedb: {}",
                  details);
    return 0;
  }

  if (libesedb_file_open(file, path_string.c_str(), LIBESEDB_OPEN_READ, &error) !=
      1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->warn("SRUM(native): не удалось открыть \"{}\" ({})", path_string,
                 details);
    return 0;
  }

  int number_of_tables = 0;
  if (libesedb_file_get_number_of_tables(file, &number_of_tables, &error) != 1 ||
      number_of_tables <= 0) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "SRUM(native): не удалось получить список таблиц: {}",
                  details);
    return 0;
  }
  free_error();

  std::unordered_map<uint64_t, std::string> id_map;

  auto parse_id_map_table = [&](libesedb_table_t* table) {
    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      return;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        ctx.config.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::optional<uint64_t> id_index;
      std::vector<std::string> values;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (!id_index.has_value() &&
              (column_lower == "idindex" || column_lower == "id_index" ||
               column_lower == "id")) {
            id_index = readRecordValueU64(record, value_entry);
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            values.push_back(*text);
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            auto ascii_strings = extractAsciiStrings(*binary, 6);
            auto utf16_strings = extractUtf16LeStrings(*binary, 6);
            values.insert(values.end(), ascii_strings.begin(), ascii_strings.end());
            values.insert(values.end(), utf16_strings.begin(), utf16_strings.end());
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (!id_index.has_value()) continue;

      std::string best_value;
      for (std::string value : values) {
        value = sanitizeUtf8Value(std::move(value));
        if (value.empty()) continue;
        if (looksLikeSid(value)) {
          best_value = value;
          break;
        }
        if (auto executable = extractExecutableFromCommand(value);
            executable.has_value()) {
          best_value = *executable;
          break;
        }
      }

      if (!best_value.empty()) {
        id_map[*id_index] = best_value;
      }
    }
  };

  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      parse_id_map_table(table);
    }

    libesedb_table_free(&table, nullptr);
  }

  std::size_t collected = 0;
  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    if (collected >= ctx.config.max_candidates_per_source) break;

    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);

    if (!is_table_allowed(table_name)) {
      libesedb_table_free(&table, nullptr);
      continue;
    }
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        ctx.config.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      if (collected >= ctx.config.max_candidates_per_source) break;

      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::string row_timestamp;
      std::string row_sid;
      std::vector<std::string> row_executables;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (auto filetime_value =
                  readRecordValueFiletimeString(record, value_entry);
              filetime_value.has_value() &&
              (row_timestamp.empty() ||
               containsIgnoreCase(column_name, "time") ||
               containsIgnoreCase(column_name, "date") ||
               containsIgnoreCase(column_name, "stamp"))) {
            row_timestamp = *filetime_value;
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            std::string value = *text;
            if (row_sid.empty() && looksLikeSid(value) &&
                (containsIgnoreCase(column_name, "sid") ||
                 containsIgnoreCase(column_name, "user"))) {
              row_sid = value;
            }

            if (auto executable = extractExecutableFromCommand(value);
                executable.has_value()) {
              appendUniqueToken(row_executables, *executable);
            }
          }

          if (auto numeric_value = readRecordValueU64(record, value_entry);
              numeric_value.has_value()) {
            if (const auto it = id_map.find(*numeric_value); it != id_map.end()) {
              if (row_sid.empty() && looksLikeSid(it->second)) {
                row_sid = it->second;
              }
              if (auto executable = extractExecutableFromCommand(it->second);
                  executable.has_value()) {
                appendUniqueToken(row_executables, *executable);
              }
            }
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            const auto binary_candidates = extractExecutableCandidatesFromBinary(
                *binary, ctx.config.max_candidates_per_source);
            for (const auto& executable : binary_candidates) {
              appendUniqueToken(row_executables, executable);
            }

            if (row_sid.empty()) {
              auto ascii_strings = extractAsciiStrings(*binary, 6);
              auto utf16_strings = extractUtf16LeStrings(*binary, 6);
              ascii_strings.insert(ascii_strings.end(), utf16_strings.begin(),
                                   utf16_strings.end());
              for (std::string candidate : ascii_strings) {
                candidate = sanitizeUtf8Value(std::move(candidate));
                if (looksLikeSid(candidate)) {
                  row_sid = candidate;
                  break;
                }
              }
            }
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (row_executables.empty()) continue;
      for (const auto& executable : row_executables) {
        if (collected >= ctx.config.max_candidates_per_source) break;

        std::string details = "table=" + table_name;
        if (!row_sid.empty()) {
          details += ", sid=" + row_sid;
        }
        addExecutionEvidence(process_data, executable, "SRUM", row_timestamp,
                            details);
        collected++;
      }
    }

    libesedb_table_free(&table, nullptr);
  }

  close_file();
  return collected;
#endif
}

}  // anonymous namespace

void SrumCollector::collect(const ExecutionEvidenceContext& ctx,
                            std::unordered_map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const fs::path srum_path = fs::path(ctx.disk_root) / ctx.config.srum_path;
  const auto resolved = findPathCaseInsensitive(srum_path);
  if (!resolved.has_value()) return;

  std::size_t collected = 0;

  collected = collectSrumNative(*resolved, process_data, ctx);
  if (collected > 0) {
    logger->info("SRUM(native): добавлено {} кандидат(ов)", collected);
    return;
  }

  // Phase 1.4: try structured ESE B-tree page parser before raw binary scan.
  collected = collectSrumEseStructured(*resolved, process_data, ctx);
  if (collected > 0) {
    logger->info("SRUM(ese_structured): добавлено {} кандидат(ов)", collected);
    return;
  }

  collected = collectSrumBinaryFallback(*resolved, process_data, ctx);
  logger->info("SRUM(binary): добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
