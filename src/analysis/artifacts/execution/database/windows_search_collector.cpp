/// @file windows_search_collector.cpp
/// @brief Реализация WindowsSearchCollector.
#include "windows_search_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>
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
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;

namespace {

std::size_t collectWindowsSearchBinaryFallback(
    const fs::path& windows_search_path,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const ExecutionEvidenceContext& ctx) {
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 32 * 1024 * 1024);
  const auto data = readFilePrefix(windows_search_path, max_bytes);
  if (!data.has_value()) return 0;

  std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
      *data, ctx.config.max_candidates_per_source);
  if (candidates.empty()) {
    const auto readable = collectReadableStrings(*data, 6);
    for (const auto& line : readable) {
      if (auto executable = tryExtractExecutableFromDecoratedText(line);
          executable.has_value()) {
        appendUniqueToken(candidates, *executable);
      }
    }
  }

  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(windows_search_path, ec));

  for (const auto& executable : candidates) {
    if (!isLikelyExecutionPath(executable)) continue;
    addExecutionEvidence(process_data, executable, "WindowsSearch", timestamp,
                        "search=Windows.edb (binary)");
  }
  return candidates.size();
}

std::size_t collectWindowsSearchNative(
    const fs::path& windows_search_path,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const ExecutionEvidenceContext& ctx) {
#if !defined(PROGRAM_TRACES_HAVE_LIBESEDB) || !PROGRAM_TRACES_HAVE_LIBESEDB
  static_cast<void>(windows_search_path);
  static_cast<void>(process_data);
  static_cast<void>(ctx);
  return 0;
#else
  const auto logger = GlobalLogger::get();

  const std::string path_string = windows_search_path.string();
  if (path_string.empty()) return 0;

  std::unordered_set<std::string> table_allowlist_lower;
  for (std::string table_name : ctx.config.windows_search_table_allowlist) {
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
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "WindowsSearch(native): не удалось инициализировать libesedb: {}",
        details);
    return 0;
  }

  if (libesedb_file_open(file, path_string.c_str(), LIBESEDB_OPEN_READ, &error) !=
      1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->warn("WindowsSearch(native): не удалось открыть \"{}\" ({})",
                 path_string, details);
    return 0;
  }

  int number_of_tables = 0;
  if (libesedb_file_get_number_of_tables(file, &number_of_tables, &error) != 1 ||
      number_of_tables <= 0) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "WindowsSearch(native): не удалось получить список таблиц: {}",
        details);
    return 0;
  }
  free_error();

  std::size_t collected = 0;
  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    if (collected >= ctx.config.max_candidates_per_source) break;

    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    if (!is_table_allowed(table_name)) {
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
        ctx.config.windows_search_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      if (collected >= ctx.config.max_candidates_per_source) break;

      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::string row_timestamp;
      std::vector<std::string> row_executables;
      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";

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
            if (auto executable = extractExecutableFromCommand(*text);
                executable.has_value()) {
              appendUniqueToken(row_executables, *executable);
            }
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            const auto candidates = extractExecutableCandidatesFromBinary(
                *binary, ctx.config.max_candidates_per_source);
            for (const auto& executable : candidates) {
              appendUniqueToken(row_executables, executable);
            }
          }
        }
      }

      libesedb_record_free(&record, nullptr);
      if (row_executables.empty()) continue;

      for (const auto& executable : row_executables) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        if (!isLikelyExecutionPath(executable)) continue;
        addExecutionEvidence(process_data, executable, "WindowsSearch",
                            row_timestamp, "table=" + table_name);
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

void WindowsSearchCollector::collect(const ExecutionEvidenceContext& ctx,
                                     std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_windows_search) return;
  const auto logger = GlobalLogger::get();
  const fs::path windows_search_path =
      fs::path(ctx.disk_root) / ctx.config.windows_search_path;
  const auto resolved = findPathCaseInsensitive(windows_search_path);
  if (!resolved.has_value()) {
    logger->info("WindowsSearch: добавлено 0 кандидат(ов)");
    return;
  }

  std::size_t collected = 0;
  bool native_attempted = false;
  if (ctx.config.enable_windows_search_native_parser) {
    native_attempted = true;
    collected = collectWindowsSearchNative(*resolved, process_data, ctx);
    if (collected > 0) {
      logger->info("WindowsSearch(native): добавлено {} кандидат(ов)", collected);
      return;
    }
  }

  if (!ctx.config.windows_search_fallback_to_binary_on_native_failure &&
      native_attempted) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "WindowsSearch fallback отключен, бинарный режим не используется после "
        "неуспеха native-парсера");
    return;
  }

  collected = collectWindowsSearchBinaryFallback(*resolved, process_data, ctx);
  logger->info("WindowsSearch(binary): добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
