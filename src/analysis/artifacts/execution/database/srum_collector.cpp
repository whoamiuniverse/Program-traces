/// @file srum_collector.cpp
/// @brief Реализация SrumCollector.
#include "srum_collector.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>

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
  if (!ctx.config.enable_srum) return;
  const auto logger = GlobalLogger::get();
  const fs::path srum_path = fs::path(ctx.disk_root) / ctx.config.srum_path;
  const auto resolved = findPathCaseInsensitive(srum_path);
  if (!resolved.has_value()) return;

  std::size_t collected = 0;
  bool native_attempted = false;

  if (ctx.config.enable_srum_native_parser) {
    native_attempted = true;
    collected = collectSrumNative(*resolved, process_data, ctx);
    if (collected > 0) {
      logger->info("SRUM(native): добавлено {} кандидат(ов)", collected);
      return;
    }
  }

  if (!ctx.config.srum_fallback_to_binary_on_native_failure &&
      native_attempted) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "SRUM fallback отключен, бинарный режим не используется после "
        "неуспеха native-парсера");
    return;
  }

  collected = collectSrumBinaryFallback(*resolved, process_data, ctx);
  logger->info("SRUM(binary): добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
