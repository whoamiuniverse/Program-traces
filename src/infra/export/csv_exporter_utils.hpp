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
  std::string executable_name;  ///< Каноническое имя исполняемого файла.
  std::set<std::string> paths;  ///< Все обнаруженные пути к файлу/команде.
  std::vector<std::string> run_times;  ///< Метки времени запусков процесса.
  std::set<std::string> users;  ///< Набор имён пользователей, связанных с запуском.
  std::set<std::string> user_sids;  ///< SID пользователей, обнаруженных в артефактах.
  std::set<std::string> logon_ids;  ///< Идентификаторы логон-сессий (LogonId).
  std::set<std::string> logon_types;  ///< Типы входа (Interactive/Service/...).
  std::set<std::string> elevation_types;  ///< Тип повышения привилегий токена.
  std::set<std::string> elevated_tokens;  ///< Флаг/тип elevated token.
  std::set<std::string> integrity_levels;  ///< Уровни целостности токена.
  std::set<std::string> privileges;  ///< Набор привилегий процесса.
  std::set<std::string> autorun_locations;  ///< Источники автозапуска.
  std::vector<NetworkConnection>
      network_connections;  ///< Сетевые подключения процесса.
  std::set<std::string>
      network_timeline_artifacts;  ///< Timeline-артефакты сетевой активности.
  std::set<std::string>
      network_context_sources;  ///< Источники сетевого контекста (EventLog/SRUM/...).
  std::set<std::string>
      network_profile_artifacts;  ///< Артефакты профилей сети/интерфейсов.
  std::vector<PrefetchAnalysis::VolumeInfo>
      volumes;  ///< Список томов из Prefetch, связанных с запуском.
  std::vector<PrefetchAnalysis::FileMetric>
      metrics;  ///< Метрики файлов из Prefetch (path/hash/size/source).
  uint32_t run_count = 0;  ///< Итоговое число запусков.
  std::set<std::string> versions;  ///< Обнаруженные версии ПО.
  std::set<std::string> hashes;  ///< Хэши бинарного файла.
  std::set<uint64_t> file_sizes;  ///< Размеры файла в байтах.
  bool has_deleted_trace = false;  ///< Признак следов удаления/отсутствия файла на диске.
  std::set<std::string> evidence_sources;  ///< Источники доказательств по процессу.
  std::set<std::string> timeline_artifacts;  ///< Timeline-артефакты исполнения.
  std::set<std::string> recovered_from;  ///< Источники recovery (USN/VSS/hiber/...).
  std::string first_seen_utc;  ///< Самое раннее время наблюдения (UTC).
  std::string last_seen_utc;   ///< Самое позднее время наблюдения (UTC).
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

/// @brief Извлекает имя файла из полного пути.
std::string getFilenameFromPath(const std::string& path);

/// @brief Преобразует тип тома в строковое представление.
std::string volumeTypeToString(uint32_t type);

/// @brief Нормализует имя источника артефакта к каноническому виду.
std::string normalizeEvidenceSource(std::string source);

}  // namespace CsvExporterUtils

}  // namespace WindowsDiskAnalysis
