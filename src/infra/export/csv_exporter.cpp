/// @file csv_exporter.cpp
/// @brief Реализация экспорта агрегированных артефактов в CSV.

#include "csv_exporter.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "common/path_utils.hpp"
#include "csv_exporter_filtering.hpp"
#include "csv_exporter_utils.hpp"
#include "errors/csv_export_exception.hpp"

using namespace PrefetchAnalysis;
using namespace WindowsDiskAnalysis::CsvExporterUtils;
using namespace WindowsDiskAnalysis::CsvExporterFiltering;

namespace {

constexpr char kCsvDelimiter = ';';
constexpr std::string_view kListSeparator = " | ";
constexpr std::string_view kNotAvailable = "N/A";
constexpr std::string_view kMissingPort = "-";
constexpr std::string_view kNetworkEventPrefix = "[NetworkEvent] ";

constexpr std::string_view kCsvHeader =
    "ИсполняемыйФайл;Пути;Версии;Хэши;РазмерФайла;ВременаЗапуска;FirstSeenUTC;"
    "LastSeenUTC;TimelineArtifacts;RecoveredFrom;Users;UserSIDs;LogonIDs;"
    "LogonTypes;ElevationType;ElevatedToken;IntegrityLevel;Privileges;"
    "Автозагрузка;СледыУдаления;КоличествоЗапусков;Тома(серийный:тип);"
    "СетевыеПодключения;NetworkTimelineArtifacts;NetworkContextSources;"
    "NetworkProfiles;ФайловыеМетрики;EvidenceSources;"
    "TamperFlags\n";

constexpr std::string_view kRecoveryCsvHeader =
    "ExecutablePath;Source;RecoveredFrom;Timestamp;Details;TamperFlag\n";

std::string escapeCsvField(std::string_view value) {
  if (value.empty()) {
    return {};
  }

  std::string result;
  result.reserve(value.size() + 2);
  result.push_back('"');

  for (const char c : value) {
    if (c == '\n' || c == '\r') {
      result.push_back(' ');
      continue;
    }

    if (c == '"') {
      result.append("\"\"");
    } else {
      result.push_back(c);
    }
  }

  result.push_back('"');
  return result;
}

void writeCsvHeader(std::ofstream& file) { file << kCsvHeader; }

void writeRecoveryCsvHeader(std::ofstream& file) { file << kRecoveryCsvHeader; }

template <typename Container>
std::string joinStrings(const Container& container) {
  size_t count = 0;
  size_t total_size = 0;
  for (const auto& value : container) {
    if (value.empty()) {
      continue;
    }
    total_size += value.size();
    ++count;
  }

  if (count == 0) {
    return {};
  }

  total_size += (count - 1) * kListSeparator.size();
  std::string out;
  out.reserve(total_size);

  bool first = true;
  for (const auto& value : container) {
    if (value.empty()) {
      continue;
    }
    if (!first) {
      out.append(kListSeparator);
    }
    out.append(value);
    first = false;
  }

  return out;
}

std::string joinUint64Values(const std::set<uint64_t>& values) {
  if (values.empty()) {
    return {};
  }

  std::string out;
  out.reserve(values.size() * 20 + (values.size() - 1) * kListSeparator.size());

  bool first = true;
  for (const uint64_t value : values) {
    if (!first) {
      out.append(kListSeparator);
    }
    out.append(std::to_string(value));
    first = false;
  }

  return out;
}

std::string serializeAutorunValue(const std::set<std::string>& locations) {
  if (locations.empty()) {
    return "Нет";
  }

  size_t total_size = 4;  // "Да()"
  bool first = true;
  for (const auto& location : locations) {
    total_size += location.size();
    if (!first) {
      total_size += 2;  // ", "
    }
    first = false;
  }

  std::string out;
  out.reserve(total_size);
  out.append("Да(");

  first = true;
  for (const auto& location : locations) {
    if (!first) {
      out.append(", ");
    }
    out.append(location);
    first = false;
  }

  out.push_back(')');
  return out;
}

std::string formatNetworkPort(const uint16_t value) {
  return value == 0 ? std::string(kMissingPort) : std::to_string(value);
}

std::string_view valueOrNotAvailable(const std::string& value) noexcept {
  return value.empty() ? kNotAvailable : std::string_view(value);
}

std::string serializeNetworkValue(
    const WindowsDiskAnalysis::NetworkConnection& conn,
    const bool include_timestamp, const bool include_application,
    const bool include_prefix) {
  const std::string source_port = formatNetworkPort(conn.source_port);
  const std::string dest_port = formatNetworkPort(conn.dest_port);
  const std::string event_id = std::to_string(conn.event_id);
  const std::string process_id = std::to_string(conn.process_id);

  const std::string_view protocol = valueOrNotAvailable(conn.protocol);
  const std::string_view source_ip = valueOrNotAvailable(conn.source_ip);
  const std::string_view dest_ip = valueOrNotAvailable(conn.dest_ip);
  const std::string_view direction = valueOrNotAvailable(conn.direction);
  const std::string_view action = valueOrNotAvailable(conn.action);
  const std::string_view application = valueOrNotAvailable(conn.application);

  size_t reserve_size = event_id.size() + process_id.size() + source_port.size() +
                        dest_port.size() + protocol.size() + source_ip.size() +
                        dest_ip.size() + direction.size() + action.size() + 48;
  if (include_timestamp) {
    reserve_size += conn.timestamp.size() + 4;  // " ts="
  }
  if (include_application) {
    reserve_size += application.size() + 5;  // " app="
  }
  if (include_prefix) {
    reserve_size += kNetworkEventPrefix.size();
  }

  std::string out;
  out.reserve(reserve_size);
  if (include_prefix) {
    out.append(kNetworkEventPrefix);
  }
  out.append("id=");
  out.append(event_id);
  if (include_timestamp) {
    out.append(" ts=");
    out.append(conn.timestamp);
  }
  out.push_back(' ');
  out.append(protocol);
  out.push_back(' ');
  out.append(source_ip);
  out.push_back(':');
  out.append(source_port);
  out.append("->");
  out.append(dest_ip);
  out.push_back(':');
  out.append(dest_port);
  out.append(" pid=");
  out.append(process_id);
  if (include_application) {
    out.append(" app=");
    out.append(application);
  }
  out.append(" dir=");
  out.append(direction);
  out.append(" action=");
  out.append(action);

  return out;
}

std::string serializeNetworkTimeline(
    const WindowsDiskAnalysis::NetworkConnection& conn) {
  return serializeNetworkValue(
      conn, /*include_timestamp=*/false, /*include_application=*/false,
      /*include_prefix=*/true);
}

std::string serializeNetworkSummary(
    const WindowsDiskAnalysis::NetworkConnection& conn) {
  return serializeNetworkValue(
      conn, /*include_timestamp=*/true, /*include_application=*/true,
      /*include_prefix=*/false);
}

std::string selectExecutablePathForAmcache(
    const WindowsDiskAnalysis::AmcacheEntry& entry) {
  const auto pick_if_valid = [](const std::string& raw_path) -> std::string {
    if (raw_path.empty()) {
      return {};
    }
    const std::string normalized = normalizePath(raw_path);
    if (normalized.empty() ||
        !PathUtils::isExecutionPathCandidate(normalized)) {
      return {};
    }
    return raw_path;
  };

  if (std::string path = pick_if_valid(entry.file_path); !path.empty()) {
    return path;
  }
  if (std::string path = pick_if_valid(entry.alternate_path); !path.empty()) {
    return path;
  }
  return {};
}

void writeAggregatedRow(std::ofstream& file, const std::string& aggregation_key,
                        const WindowsDiskAnalysis::AggregatedData& row) {
  const std::string_view filename =
      row.executable_name.empty() ? std::string_view(aggregation_key)
                                  : std::string_view(row.executable_name);

  const std::string paths_str = joinStrings(row.paths);
  const std::string versions_str = joinStrings(row.versions);
  const std::string hashes_str = joinStrings(row.hashes);
  const std::string file_sizes_str = joinUint64Values(row.file_sizes);

  std::vector<std::string> unique_run_times = row.run_times;
  sortAndUnique(unique_run_times);
  const std::string run_times_str = joinStrings(unique_run_times);

  const std::string users_str = joinStrings(row.users);
  const std::string user_sids_str = joinStrings(row.user_sids);
  const std::string logon_ids_str = joinStrings(row.logon_ids);
  const std::string logon_types_str = joinStrings(row.logon_types);
  const std::string elevation_types_str = joinStrings(row.elevation_types);
  const std::string elevated_tokens_str = joinStrings(row.elevated_tokens);
  const std::string integrity_levels_str = joinStrings(row.integrity_levels);
  const std::string privileges_str = joinStrings(row.privileges);

  const std::string autorun_str = serializeAutorunValue(row.autorun_locations);
  const std::string_view deleted_str = row.has_deleted_trace ? "Да" : "Нет";

  std::vector<std::string> network_values;
  network_values.reserve(row.network_connections.size());
  for (const auto& conn : row.network_connections) {
    network_values.push_back(serializeNetworkSummary(conn));
  }
  sortAndUnique(network_values);

  const std::string network_str = joinStrings(network_values);
  const std::string network_timeline_artifacts_str =
      joinStrings(row.network_timeline_artifacts);
  const std::string network_context_sources_str =
      joinStrings(row.network_context_sources);
  const std::string network_profiles_str =
      joinStrings(row.network_profile_artifacts);

  std::vector<std::string> volume_values;
  volume_values.reserve(row.volumes.size());
  for (const auto& vol : row.volumes) {
    volume_values.push_back(std::to_string(vol.getSerialNumber()) + ":" +
                            volumeTypeToString(vol.getVolumeType()));
  }
  sortAndUnique(volume_values);
  const std::string volumes_str = joinStrings(volume_values);

  std::vector<std::string> metric_values = buildMetricValuesForCsv(row.metrics);
  const std::string metrics_str = joinStrings(metric_values);

  const std::string timeline_artifacts_str = joinStrings(row.timeline_artifacts);
  const std::string recovered_from_str = joinStrings(row.recovered_from);
  const std::string evidence_sources_str = joinStrings(row.evidence_sources);
  const std::string tamper_flags_str = joinStrings(row.tamper_flags);

  const auto writeEscapedField = [&](const std::string_view value) {
    file << escapeCsvField(value) << kCsvDelimiter;
  };

  writeEscapedField(filename);
  writeEscapedField(paths_str);
  writeEscapedField(versions_str);
  writeEscapedField(hashes_str);
  writeEscapedField(file_sizes_str);
  writeEscapedField(run_times_str);
  writeEscapedField(row.first_seen_utc);
  writeEscapedField(row.last_seen_utc);
  writeEscapedField(timeline_artifacts_str);
  writeEscapedField(recovered_from_str);
  writeEscapedField(users_str);
  writeEscapedField(user_sids_str);
  writeEscapedField(logon_ids_str);
  writeEscapedField(logon_types_str);
  writeEscapedField(elevation_types_str);
  writeEscapedField(elevated_tokens_str);
  writeEscapedField(integrity_levels_str);
  writeEscapedField(privileges_str);
  writeEscapedField(autorun_str);
  writeEscapedField(deleted_str);

  file << row.run_count << kCsvDelimiter;

  writeEscapedField(volumes_str);
  writeEscapedField(network_str);
  writeEscapedField(network_timeline_artifacts_str);
  writeEscapedField(network_context_sources_str);
  writeEscapedField(network_profiles_str);
  writeEscapedField(metrics_str);
  writeEscapedField(evidence_sources_str);
  file << escapeCsvField(tamper_flags_str) << '\n';
}

std::filesystem::path buildRecoveryOutputPath(const std::string& output_path) {
  const std::filesystem::path base_path(output_path);
  const std::filesystem::path parent = base_path.parent_path();
  const std::string stem = base_path.stem().empty()
                               ? base_path.filename().string()
                               : base_path.stem().string();
  const std::string extension =
      base_path.has_extension() ? base_path.extension().string() : ".csv";
  return parent / (stem + "_recovery" + extension);
}

void writeRecoveryRows(std::ofstream& file,
                       const std::vector<WindowsDiskAnalysis::RecoveryEvidence>&
                           recovery_evidence) {
  for (const auto& entry : recovery_evidence) {
    file << escapeCsvField(entry.executable_path) << kCsvDelimiter
         << escapeCsvField(entry.source) << kCsvDelimiter
         << escapeCsvField(entry.recovered_from) << kCsvDelimiter
         << escapeCsvField(entry.timestamp) << kCsvDelimiter
         << escapeCsvField(entry.details) << kCsvDelimiter
         << escapeCsvField(entry.tamper_flag) << '\n';
  }
}

}  // namespace

namespace WindowsDiskAnalysis {

void CSVExporter::exportToCSV(
    const std::string& output_path,
    const std::vector<AutorunEntry>& autorun_entries,
    const std::unordered_map<std::string, ProcessInfo>& process_data,
    const std::vector<NetworkConnection>& network_connections,
    const std::vector<AmcacheEntry>& amcache_entries,
    const std::vector<RecoveryEvidence>& recovery_evidence) {
  std::ofstream file(output_path, std::ios::binary);
  if (!file.is_open()) {
    throw FileOpenException(output_path);
  }

  try {
    // BOM нужен для корректного чтения UTF-8 заголовков в Excel/Windows
    file.write("\xEF\xBB\xBF", 3);
    writeCsvHeader(file);

    // Основная карта для агрегации данных по нормализованному идентификатору
    // процесса.
    // Приоритет: полный путь (если есть), иначе имя файла.
    // unordered_map: O(1) lookup vs O(log n) у std::map — существенно на
    // дисках с тысячами процессов (каждая из 4 секций делает lookup per entry).
    std::unordered_map<std::string, AggregatedData> aggregated_data;
    aggregated_data.reserve(
        process_data.size() + autorun_entries.size() / 4 + amcache_entries.size());

    // Обработка всех типов данных с объединением по имени файла
    auto processEntry = [&](const std::string& path, auto processor) {
      std::string norm_path = normalizePath(path);
      if (norm_path.empty()) return;

      // Получаем имя файла - основной ключ для агрегации
      std::string filename = getFilenameFromPath(norm_path);
      if (filename.empty()) return;

      const bool has_explicit_path = PathUtils::hasPathContext(norm_path);
      const std::string aggregation_key =
          toLowerAscii(has_explicit_path ? norm_path : filename);

      // Обрабатываем данные
      auto& bucket = aggregated_data[aggregation_key];
      if (bucket.executable_name.empty()) {
        bucket.executable_name = filename;
      }

      processor(bucket, norm_path);
    };

    // 1. Обрабатываем данные автозагрузки
    for (const auto& entry : autorun_entries) {
      processEntry(entry.path,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.autorun_locations.insert(entry.location);
                     addEvidenceSource(data, "Autorun");
                     data.timeline_artifacts.insert("[Autorun] " + entry.location);
                   });
    }

    // 2. Обрабатываем данные процессов
    for (const auto& [path, info] : process_data) {
      processEntry(
          path, [&](AggregatedData& data, const std::string& normalized_path) {
            data.paths.insert(normalized_path);
            data.run_times.insert(data.run_times.end(), info.run_times.begin(),
                                  info.run_times.end());
            data.run_count += info.run_count;
            data.volumes.insert(data.volumes.end(), info.volumes.begin(),
                                info.volumes.end());
            data.metrics.insert(data.metrics.end(), info.metrics.begin(),
                                info.metrics.end());
            data.users.insert(info.users.begin(), info.users.end());
            data.user_sids.insert(info.user_sids.begin(), info.user_sids.end());
            data.logon_ids.insert(info.logon_ids.begin(), info.logon_ids.end());
            data.logon_types.insert(info.logon_types.begin(), info.logon_types.end());
            data.privileges.insert(info.privileges.begin(), info.privileges.end());
            if (!info.elevation_type.empty()) {
              data.elevation_types.insert(info.elevation_type);
            }
            if (!info.elevated_token.empty()) {
              data.elevated_tokens.insert(info.elevated_token);
            }
            if (!info.integrity_level.empty()) {
              data.integrity_levels.insert(info.integrity_level);
            }

            for (const auto& source : info.evidence_sources) {
              const std::string normalized_source =
                  normalizeEvidenceSource(source);
              addEvidenceSource(data, normalized_source);
              if (isNetworkContextSource(normalized_source)) {
                data.network_context_sources.insert(normalized_source);
              }
            }
            for (const auto& flag : info.tamper_flags) {
              addTamperFlag(data, flag);
            }
            for (const auto& timeline : info.timeline_artifacts) {
              if (!timeline.empty()) {
                data.timeline_artifacts.insert(timeline);
                if (isNetworkTimelineArtifact(timeline)) {
                  data.network_timeline_artifacts.insert(timeline);
                  const std::string lowered = toLowerAscii(timeline);
                  if (lowered.find("[networkprofile]") != std::string::npos) {
                    data.network_profile_artifacts.insert(timeline);
                  }
                }
              }
            }
            for (const auto& recovered_from : info.recovered_from) {
              if (!recovered_from.empty()) {
                data.recovered_from.insert(recovered_from);
              }
            }

            updateRowFirstSeen(data, info.first_seen_utc);
            updateRowLastSeen(data, info.last_seen_utc);
            for (const auto& timestamp : info.run_times) {
              updateRowFirstSeen(data, timestamp);
              updateRowLastSeen(data, timestamp);
            }

            // Fallback для старых источников, где evidence_sources еще не
            // заполнены на этапе сбора.
            if (info.evidence_sources.empty()) {
              if (!info.metrics.empty() || !info.volumes.empty()) {
                addEvidenceSource(data, "Prefetch");
              } else if (info.run_count > 0 || !info.run_times.empty()) {
                addEvidenceSource(data, "EventLog");
              }
            }

          });
    }

    // 3. Обрабатываем сетевые подключения
    for (const auto& conn : network_connections) {
      std::string network_key = conn.process_name;
      if (network_key.empty()) {
        network_key = conn.application;
      }
      if (network_key.empty()) continue;

      processEntry(network_key,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.network_connections.push_back(conn);
                     addEvidenceSource(data, "NetworkEvent");
                     data.network_context_sources.insert("NetworkEvent");

                     const std::string timeline_value =
                         serializeNetworkTimeline(conn);
                     data.timeline_artifacts.insert(timeline_value);
                     data.network_timeline_artifacts.insert(timeline_value);
                   });
    }

    // 4. Обрабатываем данные Amcache - добавляем версии, хэши, размеры и время
    // изменения
    for (const auto& entry : amcache_entries) {
      // Принимаем только записи, где известен путь к исполняемому файлу.
      // Приложения/пакеты из InventoryApplication без пути к exe
      // не должны создавать отдельные process-строки в CSV.
      const std::string path = selectExecutablePathForAmcache(entry);
      if (path.empty()) continue;

      processEntry(path,
                   [&](AggregatedData& data, const std::string& norm_path) {
                     data.paths.insert(norm_path);
                     addEvidenceSource(
                         data, entry.source.empty() ? "Amcache" : entry.source);

                     // Добавляем версии и хэши
                     if (!entry.version.empty()) {
                       data.versions.insert(entry.version);
                     }
                     if (!entry.file_hash.empty()) {
                       data.hashes.insert(entry.file_hash);
                     }

                     // Добавляем размеры файлов
                     if (entry.file_size > 0) {
                       data.file_sizes.insert(entry.file_size);
                     }

                     if (!entry.modification_time_str.empty()) {
                       data.run_times.push_back(entry.modification_time_str);
                       updateRowFirstSeen(data, entry.modification_time_str);
                       updateRowLastSeen(data, entry.modification_time_str);
                       data.timeline_artifacts.insert(
                           "[" +
                           (entry.source.empty() ? std::string("Amcache")
                                                 : entry.source) +
                           "] " + entry.modification_time_str);
                     }

                     if (entry.is_deleted) {
                       data.has_deleted_trace = true;
                     }
                   });
    }

    // 5. Генерируем выходные данные
    for (const auto& [aggregation_key, data] : aggregated_data) {
      writeAggregatedRow(file, aggregation_key, data);
    }
  } catch (const std::exception& e) {
    throw CsvExportException(std::string("Ошибка при экспорте данных: ") +
                             e.what());
  }

  const std::filesystem::path recovery_output_path =
      buildRecoveryOutputPath(output_path);
  std::ofstream recovery_file(recovery_output_path, std::ios::binary);
  if (!recovery_file.is_open()) {
    throw FileOpenException(recovery_output_path.string());
  }
  recovery_file.write("\xEF\xBB\xBF", 3);
  writeRecoveryCsvHeader(recovery_file);
  writeRecoveryRows(recovery_file, recovery_evidence);
}

}  // namespace WindowsDiskAnalysis
