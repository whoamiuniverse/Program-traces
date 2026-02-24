#include "csv_exporter.hpp"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

#include "../../core/analysis/program_analysis/data/analysis_data.hpp"
#include "../../core/exceptions/csv_export_exception.hpp"

namespace fs = std::filesystem;
using namespace PrefetchAnalysis;

namespace {

struct AggregatedData {
  std::set<std::string> paths;  // Все пути для данного файла
  std::vector<std::string> run_times;
  std::set<std::string> autorun_locations;
  std::vector<WindowsDiskAnalysis::NetworkConnection> network_connections;
  std::vector<VolumeInfo> volumes;
  std::vector<FileMetric> metrics;
  uint32_t run_count = 0;
  std::set<std::string> versions;
  std::set<std::string> hashes;
  std::set<uint64_t> file_sizes;  // Размеры файлов
  bool has_deleted_trace = false;
};

std::string normalizePath(const std::string& path) {
  if (path.empty()) return "";

  std::string result = path;
  std::ranges::transform(result, result.begin(),
                         [](unsigned char c) { return std::tolower(c); });

  std::ranges::replace(result, '/', '\\');

  // Удаление начальных и конечных пробелов/кавычек
  auto start = result.find_first_not_of(" \"");
  auto end = result.find_last_not_of(" \"");

  if (start == std::string::npos || end == std::string::npos) return "";

  return result.substr(start, end - start + 1);
}

// Функция для извлечения имени файла из пути
std::string getFilenameFromPath(const std::string& path) {
  fs::path p(path);
  return p.filename().string();
}

std::string volumeTypeToString(uint32_t type) {
  switch (static_cast<VolumeType>(type)) {
    case VolumeType::FIXED:
      return "FIXED";
    case VolumeType::REMOVABLE:
      return "REMOVABLE";
    case VolumeType::NETWORK:
      return "NETWORK";
    case VolumeType::OPTICAL:
      return "CDROM";
    case VolumeType::RAMDISK:
      return "RAM";
    case VolumeType::SYSTEM:
      return "SYSTEM";
    case VolumeType::TEMPORARY:
      return "TEMPORARY";
    case VolumeType::VIRTUAL:
      return "VIRTUAL";
    default:
      return "UNKNOWN";
  }
}

std::string accessFlagsToString(uint32_t flags) {
  std::string result;
  if (flags & static_cast<uint32_t>(FileMetricAccess::READ)) result += "READ,";
  if (flags & static_cast<uint32_t>(FileMetricAccess::WRITE))
    result += "WRITE,";
  if (flags & static_cast<uint32_t>(FileMetricAccess::EXECUTE))
    result += "EXECUTE,";
  if (flags & static_cast<uint32_t>(FileMetricAccess::DELETE))
    result += "DELETE,";

  if (!result.empty()) result.pop_back();
  return result;
}

}  // namespace

namespace WindowsDiskAnalysis {

void CSVExporter::exportToCSV(
    const std::string& output_path,
    const std::vector<AutorunEntry>& autorun_entries,
    const std::map<std::string, ProcessInfo>& process_data,
    const std::vector<NetworkConnection>& network_connections,
    const std::vector<AmcacheEntry>& amcache_entries) {
  std::ofstream file(output_path);
  if (!file.is_open()) {
    throw FileOpenException(output_path);
  }

  try {
    // Обновлённый заголовок CSV с новыми полями
    file << "ИсполняемыйФайл,Версии,Хэши,РазмерФайла,ВременаЗапуска,"
            "Автозагрузка,"
         << "КоличествоЗапусков,"
         << "Тома(серийный:тип),СетевыеПодключения,ФайловыеМетрики\n";

    // Основная карта для агрегации данных по имени файла
    std::map<std::string, AggregatedData> aggregated_data;

    // Обработка всех типов данных с объединением по имени файла
    auto processEntry = [&](const std::string& path, auto processor) {
      std::string norm_path = normalizePath(path);
      if (norm_path.empty()) return;

      // Получаем имя файла - основной ключ для агрегации
      std::string filename = getFilenameFromPath(norm_path);

      // Обрабатываем данные
      processor(aggregated_data[filename], norm_path);
    };

    // 1. Обрабатываем данные автозагрузки
    for (const auto& entry : autorun_entries) {
      processEntry(entry.path,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.autorun_locations.insert(entry.location);
                   });
    }

    // 2. Обрабатываем данные процессов
    for (const auto& [path, info] : process_data) {
      processEntry(path, [&](AggregatedData& data, const std::string& path) {
        data.paths.insert(path);
        data.run_times.insert(data.run_times.end(), info.run_times.begin(),
                              info.run_times.end());
        data.run_count += info.run_count;
        data.volumes.insert(data.volumes.end(), info.volumes.begin(),
                            info.volumes.end());
        data.metrics.insert(data.metrics.end(), info.metrics.begin(),
                            info.metrics.end());
      });
    }

    // 3. Обрабатываем сетевые подключения
    for (const auto& conn : network_connections) {
      processEntry(conn.process_name,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.network_connections.push_back(conn);
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
                     }

                     if (entry.is_deleted) {
                       data.has_deleted_trace = true;
                     }
                   });
    }

    // 5. Генерируем выходные данные
    for (const auto& [filename, data] : aggregated_data) {
      auto escape = [](const std::string& s) {
        if (s.empty()) return std::string();

        std::string result;
        result.reserve(s.size() + 2);
        result += '"';

        for (char c : s) {
          if (c == '"')
            result += "\"\"";
          else
            result += c;
        }

        result += '"';
        return result;
      };

      // Форматирование версий
      std::string versions_str;
      for (const auto& ver : data.versions) {
        if (!versions_str.empty()) versions_str += ";";
        versions_str += ver;
      }

      // Форматирование хэшей
      std::string hashes_str;
      for (const auto& hash : data.hashes) {
        if (!hashes_str.empty()) hashes_str += ";";
        hashes_str += hash;
      }

      // Форматирование размеров файлов
      std::string file_sizes_str;
      for (const auto& size : data.file_sizes) {
        if (!file_sizes_str.empty()) file_sizes_str += ";";
        file_sizes_str += std::to_string(size);
      }

      // Форматирование времени запуска (включая время изменения)
      std::string run_times_str;
      for (const auto& time : data.run_times) {
        if (!run_times_str.empty()) run_times_str += ";";
        run_times_str += time;
      }

      // Форматирование автозагрузки
      std::string autorun_str;
      if (!data.autorun_locations.empty()) {
        autorun_str = "Да(";
        for (const auto& location : data.autorun_locations) {
          if (autorun_str.size() > 3) autorun_str += ", ";
          autorun_str += location;
        }
        autorun_str += ")";
      } else {
        autorun_str = "Нет";
      }

      // Следы удалённых файлов
      std::string deleted_str = data.has_deleted_trace ? "Да" : "Нет";

      // Форматирование сетевых подключений
      std::string network_str;
      for (const auto& conn : data.network_connections) {
        if (!network_str.empty()) network_str += ";";
        network_str += conn.protocol + ":" + conn.local_address + "->" +
                       conn.remote_address + ":" + std::to_string(conn.port);
      }

      // Форматирование томов
      std::string volumes_str;
      for (const auto& vol : data.volumes) {
        if (!volumes_str.empty()) volumes_str += ";";
        volumes_str += std::to_string(vol.getSerialNumber()) + ":" +
                       volumeTypeToString(vol.getVolumeType()) + ":";
      }

      // Форматирование файловых метрик
      std::string metrics_str;
      for (const auto& metric : data.metrics) {
        fs::path file_path(metric.getFilename());
        std::string filename = file_path.filename().string();

        if (!metrics_str.empty()) metrics_str += ";";
        metrics_str += filename;
      }

      // Запись данных с новыми полями
      file << escape(filename) << "," << escape(versions_str) << ","
           << escape(hashes_str) << "," << escape(file_sizes_str) << ","
           << escape(run_times_str) << "," << escape(autorun_str) << ","
           << data.run_count << "," << escape(volumes_str) << ","
           << escape(network_str) << "," << escape(metrics_str) << "\n";
    }
  } catch (const std::exception& e) {
    throw CsvExportException(std::string("Ошибка при экспорте данных: ") +
                             e.what());
  }
}

}
