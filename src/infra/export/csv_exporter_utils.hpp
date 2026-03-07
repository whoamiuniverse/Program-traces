/// @file csv_exporter_utils.hpp
/// @brief Утилиты строк и путей для CSV-экспорта.

#pragma once

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"
#include "parsers/prefetch/metadata/volume_type.hpp"

namespace WindowsDiskAnalysis {

/// @brief Агрегированные данные для одной строки CSV.
struct AggregatedData {
  std::string executable_name;
  std::set<std::string> paths;
  std::vector<std::string> run_times;
  std::set<std::string> users;
  std::set<std::string> user_sids;
  std::set<std::string> logon_ids;
  std::set<std::string> logon_types;
  std::set<std::string> elevation_types;
  std::set<std::string> elevated_tokens;
  std::set<std::string> integrity_levels;
  std::set<std::string> privileges;
  std::set<std::string> autorun_locations;
  std::vector<NetworkConnection> network_connections;
  std::set<std::string> network_event_ids;
  std::set<std::string> network_timestamps;
  std::set<std::string> network_process_names;
  std::set<std::string> network_process_ids;
  std::set<std::string> network_applications;
  std::set<std::string> network_protocols;
  std::set<std::string> network_source_ips;
  std::set<std::string> network_source_ports;
  std::set<std::string> network_dest_ips;
  std::set<std::string> network_dest_ports;
  std::set<std::string> network_directions;
  std::set<std::string> network_actions;
  std::set<std::string> network_timeline_artifacts;
  std::set<std::string> network_context_sources;
  std::set<std::string> network_profile_artifacts;
  std::set<std::string> firewall_rule_artifacts;
  std::vector<PrefetchAnalysis::VolumeInfo> volumes;
  std::vector<PrefetchAnalysis::FileMetric> metrics;
  uint32_t run_count = 0;
  std::set<std::string> versions;
  std::set<std::string> hashes;
  std::set<uint64_t> file_sizes;
  bool has_deleted_trace = false;
  std::set<std::string> evidence_sources;
  std::set<std::string> tamper_flags;
  std::set<std::string> timeline_artifacts;
  std::set<std::string> recovered_from;
  std::string first_seen_utc;
  std::string last_seen_utc;
};

namespace CsvExporterUtils {

/// @brief Приводит ASCII-символ к нижнему регистру.
char toLowerAsciiChar(unsigned char c);

/// @brief Приводит ASCII-строку к нижнему регистру.
std::string toLowerAscii(std::string value);

/// @brief Сортирует вектор и удаляет дубликаты.
template <typename T>
void sortAndUnique(std::vector<T>& values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

/// @brief Нормализует путь/командную строку до пути исполняемого файла.
std::string normalizePath(const std::string& path);

/// @brief Проверяет, является ли ключ служебным контейнером network-контекста.
bool isSyntheticNetworkContextKey(const std::string& path);

/// @brief Извлекает имя файла из полного пути.
std::string getFilenameFromPath(const std::string& path);

/// @brief Преобразует тип тома в строковое представление.
std::string volumeTypeToString(uint32_t type);

/// @brief Нормализует имя источника артефакта к каноническому виду.
std::string normalizeEvidenceSource(std::string source);

}  // namespace CsvExporterUtils

}  // namespace WindowsDiskAnalysis
