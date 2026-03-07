/// @file csv_exporter.cpp
/// @brief Реализация экспорта агрегированных артефактов в CSV.

#include "csv_exporter.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "csv_exporter_filtering.hpp"
#include "csv_exporter_utils.hpp"
#include "errors/csv_export_exception.hpp"

namespace fs = std::filesystem;
using namespace PrefetchAnalysis;
using namespace WindowsDiskAnalysis::CsvExporterUtils;
using namespace WindowsDiskAnalysis::CsvExporterFiltering;

namespace {

constexpr char kCsvDelimiter = ';';
constexpr std::string_view kListSeparator = " | ";

}  // namespace

namespace WindowsDiskAnalysis {

void CSVExporter::exportToCSV(
    const std::string& output_path,
    const std::vector<AutorunEntry>& autorun_entries,
    const std::unordered_map<std::string, ProcessInfo>& process_data,
    const std::vector<NetworkConnection>& network_connections,
    const std::vector<AmcacheEntry>& amcache_entries,
    const CSVExportOptions& options) {
  std::ofstream file(output_path, std::ios::binary);
  if (!file.is_open()) {
    throw FileOpenException(output_path);
  }

  try {
    const MetricFilterRules metric_rules = buildMetricFilterRules(options);

    auto escape = [](const std::string& s) {
      if (s.empty()) return std::string();

      std::string result;
      result.reserve(s.size() + 2);
      result += '"';

      for (char c : s) {
        if (c == '\n' || c == '\r') {
          result += ' ';
          continue;
        }

        if (c == '"')
          result += "\"\"";
        else
          result += c;
      }

      result += '"';
      return result;
    };

    auto joinStrings = [](const auto& container) {
      std::string out;
      bool first = true;
      for (const auto& value : container) {
        if (value.empty()) continue;
        if (!first) out += kListSeparator;
        out += value;
        first = false;
      }
      return out;
    };

    // BOM нужен для корректного чтения UTF-8 заголовков в Excel/Windows
    file.write("\xEF\xBB\xBF", 3);

    // Заголовок CSV
    file << "ИсполняемыйФайл" << kCsvDelimiter << "Пути" << kCsvDelimiter
         << "Версии" << kCsvDelimiter << "Хэши" << kCsvDelimiter
         << "РазмерФайла" << kCsvDelimiter << "ВременаЗапуска" << kCsvDelimiter
         << "FirstSeenUTC" << kCsvDelimiter << "LastSeenUTC" << kCsvDelimiter
         << "TimelineArtifacts" << kCsvDelimiter << "RecoveredFrom"
         << kCsvDelimiter << "Users" << kCsvDelimiter << "UserSIDs"
         << kCsvDelimiter << "LogonIDs" << kCsvDelimiter << "LogonTypes"
         << kCsvDelimiter << "ElevationType" << kCsvDelimiter
         << "ElevatedToken" << kCsvDelimiter << "IntegrityLevel"
         << kCsvDelimiter << "Privileges" << kCsvDelimiter << "Автозагрузка"
         << kCsvDelimiter << "СледыУдаления" << kCsvDelimiter
         << "КоличествоЗапусков" << kCsvDelimiter << "Тома(серийный:тип)"
         << kCsvDelimiter << "СетевыеПодключения" << kCsvDelimiter
         << "NetworkEventIDs" << kCsvDelimiter << "NetworkTimestamps"
         << kCsvDelimiter << "NetworkProcessNames" << kCsvDelimiter
         << "NetworkProcessIDs" << kCsvDelimiter << "NetworkApplications"
         << kCsvDelimiter << "NetworkProtocols" << kCsvDelimiter
         << "NetworkSourceIPs" << kCsvDelimiter << "NetworkSourcePorts"
         << kCsvDelimiter << "NetworkDestIPs" << kCsvDelimiter
         << "NetworkDestPorts" << kCsvDelimiter << "NetworkDirections"
         << kCsvDelimiter << "NetworkActions" << kCsvDelimiter
         << "NetworkTimelineArtifacts" << kCsvDelimiter
         << "NetworkContextSources" << kCsvDelimiter << "NetworkProfiles"
         << kCsvDelimiter << "FirewallRules" << kCsvDelimiter
         << "ФайловыеМетрики" << kCsvDelimiter
         << "EvidenceSources" << kCsvDelimiter << "TamperFlags\n";

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

      const bool has_explicit_path =
          norm_path.find('\\') != std::string::npos ||
          norm_path.find('/') != std::string::npos ||
          (norm_path.size() >= 3 &&
           std::isalpha(static_cast<unsigned char>(norm_path[0])) != 0 &&
           norm_path[1] == ':' &&
           (norm_path[2] == '\\' || norm_path[2] == '/'));
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
      if (isSyntheticNetworkContextKey(path)) {
        continue;
      }
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
                  if (lowered.find("[firewallrule]") != std::string::npos) {
                    data.firewall_rule_artifacts.insert(timeline);
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

                     if (conn.event_id > 0) {
                       data.network_event_ids.insert(std::to_string(conn.event_id));
                     }
                     if (!conn.timestamp.empty()) {
                       data.network_timestamps.insert(conn.timestamp);
                     }
                     if (!conn.process_name.empty()) {
                       data.network_process_names.insert(conn.process_name);
                     }
                     if (conn.process_id > 0) {
                       data.network_process_ids.insert(
                           std::to_string(conn.process_id));
                     }
                     if (!conn.application.empty()) {
                       data.network_applications.insert(conn.application);
                     }
                     if (!conn.protocol.empty()) {
                       data.network_protocols.insert(conn.protocol);
                     }
                     if (!conn.source_ip.empty()) {
                       data.network_source_ips.insert(conn.source_ip);
                     }
                     if (conn.source_port > 0) {
                       data.network_source_ports.insert(
                           std::to_string(conn.source_port));
                     }
                     if (!conn.dest_ip.empty()) {
                       data.network_dest_ips.insert(conn.dest_ip);
                     }
                     if (conn.dest_port > 0) {
                       data.network_dest_ports.insert(std::to_string(conn.dest_port));
                     }
                     if (!conn.direction.empty()) {
                       data.network_directions.insert(conn.direction);
                     }
                     if (!conn.action.empty()) {
                       data.network_actions.insert(conn.action);
                     }

                     const auto port_to_string = [](const uint16_t value) {
                       return value == 0 ? std::string("-")
                                         : std::to_string(value);
                     };

                     const std::string protocol =
                         conn.protocol.empty() ? "N/A" : conn.protocol;
                     const std::string source_ip =
                         conn.source_ip.empty() ? "N/A" : conn.source_ip;
                     const std::string dest_ip =
                         conn.dest_ip.empty() ? "N/A" : conn.dest_ip;
                     const std::string direction =
                         conn.direction.empty() ? "N/A" : conn.direction;
                     const std::string action =
                         conn.action.empty() ? "N/A" : conn.action;

                     const std::string timeline_value =
                         "[NetworkEvent] id=" + std::to_string(conn.event_id) + " " +
                         protocol + " " + source_ip + ":" +
                         port_to_string(conn.source_port) + "->" + dest_ip +
                         ":" + port_to_string(conn.dest_port) + " pid=" +
                         std::to_string(conn.process_id) + " dir=" + direction +
                         " action=" + action;
                     data.timeline_artifacts.insert(timeline_value);
                     data.network_timeline_artifacts.insert(timeline_value);
                   });
    }

    // 4. Обрабатываем данные Amcache - добавляем версии, хэши, размеры и время
    // изменения
    for (const auto& entry : amcache_entries) {
      // Используем file_path как основной идентификатор
      std::string path = entry.file_path;
      if (path.empty() && !entry.name.empty()) {
        path = entry.name;  // fallback на имя файла
      }
      if (path.empty()) continue;  // пропускаем если нет идентификатора

      processEntry(path,
                   [&](AggregatedData& data, const std::string& norm_path) {
                     data.paths.insert(norm_path);
                     addEvidenceSource(data, "Amcache");

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
                           "[Amcache] " + entry.modification_time_str);
                     }

                     if (entry.is_deleted) {
                       data.has_deleted_trace = true;
                     }
                   });
    }

    // 5. Генерируем выходные данные
    for (const auto& [aggregation_key, data] : aggregated_data) {
      AggregatedData row = data;
      deriveTamperFlags(row, options);

      const std::string& filename =
          row.executable_name.empty() ? aggregation_key : row.executable_name;

      std::string paths_str = joinStrings(row.paths);
      std::string versions_str = joinStrings(row.versions);
      std::string hashes_str = joinStrings(row.hashes);

      std::vector<std::string> file_sizes;
      file_sizes.reserve(row.file_sizes.size());
      for (const auto size : row.file_sizes) {
        file_sizes.push_back(std::to_string(size));
      }
      std::string file_sizes_str = joinStrings(file_sizes);

      // Форматирование времени запуска (включая время изменения)
      std::vector<std::string> unique_run_times = row.run_times;
      sortAndUnique(unique_run_times);
      std::string run_times_str = joinStrings(unique_run_times);
      std::string users_str = joinStrings(row.users);
      std::string user_sids_str = joinStrings(row.user_sids);
      std::string logon_ids_str = joinStrings(row.logon_ids);
      std::string logon_types_str = joinStrings(row.logon_types);
      std::string elevation_types_str = joinStrings(row.elevation_types);
      std::string elevated_tokens_str = joinStrings(row.elevated_tokens);
      std::string integrity_levels_str = joinStrings(row.integrity_levels);
      std::string privileges_str = joinStrings(row.privileges);

      // Форматирование автозагрузки
      std::string autorun_str;
      if (!row.autorun_locations.empty()) {
        autorun_str = "Да(";
        bool first_location = true;
        for (const auto& location : row.autorun_locations) {
          if (!first_location) autorun_str += ", ";
          autorun_str += location;
          first_location = false;
        }
        autorun_str += ")";
      } else {
        autorun_str = "Нет";
      }

      // Следы удалённых файлов
      std::string deleted_str = row.has_deleted_trace ? "Да" : "Нет";

      // Форматирование сетевых подключений
      std::vector<std::string> network_values;
      network_values.reserve(row.network_connections.size());
      const auto port_to_string = [](const uint16_t value) {
        return value == 0 ? std::string("-") : std::to_string(value);
      };
      for (const auto& conn : row.network_connections) {
        const std::string protocol = conn.protocol.empty() ? "N/A" : conn.protocol;
        const std::string source_ip =
            conn.source_ip.empty() ? "N/A" : conn.source_ip;
        const std::string dest_ip = conn.dest_ip.empty() ? "N/A" : conn.dest_ip;
        const std::string direction =
            conn.direction.empty() ? "N/A" : conn.direction;
        const std::string action = conn.action.empty() ? "N/A" : conn.action;
        const std::string application =
            conn.application.empty() ? "N/A" : conn.application;
        network_values.push_back(
            "id=" + std::to_string(conn.event_id) + " ts=" + conn.timestamp + " " +
            protocol + " " + source_ip + ":" + port_to_string(conn.source_port) +
            "->" + dest_ip + ":" + port_to_string(conn.dest_port) + " pid=" +
            std::to_string(conn.process_id) + " app=" + application +
            " dir=" + direction + " action=" + action);
      }
      sortAndUnique(network_values);
      std::string network_str = joinStrings(network_values);
      std::string network_event_ids_str = joinStrings(row.network_event_ids);
      std::string network_timestamps_str = joinStrings(row.network_timestamps);
      std::string network_process_names_str = joinStrings(row.network_process_names);
      std::string network_process_ids_str = joinStrings(row.network_process_ids);
      std::string network_applications_str = joinStrings(row.network_applications);
      std::string network_protocols_str = joinStrings(row.network_protocols);
      std::string network_source_ips_str = joinStrings(row.network_source_ips);
      std::string network_source_ports_str = joinStrings(row.network_source_ports);
      std::string network_dest_ips_str = joinStrings(row.network_dest_ips);
      std::string network_dest_ports_str = joinStrings(row.network_dest_ports);
      std::string network_directions_str = joinStrings(row.network_directions);
      std::string network_actions_str = joinStrings(row.network_actions);
      std::string network_timeline_artifacts_str =
          joinStrings(row.network_timeline_artifacts);
      std::string network_context_sources_str =
          joinStrings(row.network_context_sources);
      std::string network_profiles_str = joinStrings(row.network_profile_artifacts);
      std::string firewall_rules_str = joinStrings(row.firewall_rule_artifacts);

      // Форматирование томов
      std::vector<std::string> volume_values;
      volume_values.reserve(row.volumes.size());
      for (const auto& vol : row.volumes) {
        volume_values.push_back(std::to_string(vol.getSerialNumber()) + ":" +
                                volumeTypeToString(vol.getVolumeType()));
      }
      sortAndUnique(volume_values);
      std::string volumes_str = joinStrings(volume_values);

      // Форматирование файловых метрик
      std::vector<std::string> metric_values =
          buildMetricValuesForCsv(row.metrics, metric_rules);
      std::string metrics_str = joinStrings(metric_values);

      std::string timeline_artifacts_str = joinStrings(row.timeline_artifacts);
      std::string recovered_from_str = joinStrings(row.recovered_from);
      std::string evidence_sources_str = joinStrings(row.evidence_sources);
      std::string tamper_flags_str = joinStrings(row.tamper_flags);

      // Запись данных в строго фиксированном порядке колонок
      file << escape(filename) << kCsvDelimiter << escape(paths_str)
           << kCsvDelimiter << escape(versions_str) << kCsvDelimiter
           << escape(hashes_str) << kCsvDelimiter << escape(file_sizes_str)
           << kCsvDelimiter << escape(run_times_str) << kCsvDelimiter
           << escape(row.first_seen_utc) << kCsvDelimiter
           << escape(row.last_seen_utc) << kCsvDelimiter
           << escape(timeline_artifacts_str) << kCsvDelimiter
           << escape(recovered_from_str) << kCsvDelimiter << escape(users_str)
           << kCsvDelimiter << escape(user_sids_str) << kCsvDelimiter
           << escape(logon_ids_str) << kCsvDelimiter << escape(logon_types_str)
           << kCsvDelimiter << escape(elevation_types_str) << kCsvDelimiter
           << escape(elevated_tokens_str) << kCsvDelimiter
           << escape(integrity_levels_str) << kCsvDelimiter
           << escape(privileges_str) << kCsvDelimiter << escape(autorun_str)
           << kCsvDelimiter << escape(deleted_str)
           << kCsvDelimiter << row.run_count << kCsvDelimiter
           << escape(volumes_str) << kCsvDelimiter << escape(network_str)
           << kCsvDelimiter << escape(network_event_ids_str)
           << kCsvDelimiter << escape(network_timestamps_str)
           << kCsvDelimiter << escape(network_process_names_str)
           << kCsvDelimiter << escape(network_process_ids_str)
           << kCsvDelimiter << escape(network_applications_str)
           << kCsvDelimiter << escape(network_protocols_str)
           << kCsvDelimiter << escape(network_source_ips_str)
           << kCsvDelimiter << escape(network_source_ports_str)
           << kCsvDelimiter << escape(network_dest_ips_str)
           << kCsvDelimiter << escape(network_dest_ports_str)
           << kCsvDelimiter << escape(network_directions_str)
           << kCsvDelimiter << escape(network_actions_str)
           << kCsvDelimiter << escape(network_timeline_artifacts_str)
           << kCsvDelimiter << escape(network_context_sources_str)
           << kCsvDelimiter << escape(network_profiles_str)
           << kCsvDelimiter << escape(firewall_rules_str)
           << kCsvDelimiter << escape(metrics_str) << kCsvDelimiter
           << escape(evidence_sources_str) << kCsvDelimiter
           << escape(tamper_flags_str) << "\n";
    }
  } catch (const std::exception& e) {
    throw CsvExportException(std::string("Ошибка при экспорте данных: ") +
                             e.what());
  }
}

}  // namespace WindowsDiskAnalysis
