/// @file csv_exporter.hpp
/// @brief Класс для экспорта результатов анализа Windows в CSV формат

#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "errors/csv_export_exception.hpp"

namespace WindowsDiskAnalysis {

/// @struct CSVExportOptions
/// @brief Настройки экспорта CSV, загружаемые из config.ini
struct CSVExportOptions {
  /// @brief Максимум имён в колонке "ФайловыеМетрики" (0 = без ограничения)
  std::size_t max_metric_names = 200;

  /// @brief Префиксы для отбрасывания метрик (case-insensitive)
  std::vector<std::string> metric_skip_prefixes = {"tmp", "~tmp"};

  /// @brief Подстроки для отбрасывания метрик (case-insensitive)
  std::vector<std::string> metric_skip_contains = {".tmp"};

  /// @brief Точные имена для отбрасывания метрик (case-insensitive)
  std::vector<std::string> metric_skip_exact;

  /// @brief Отбрасывать короткие токены в верхнем регистре без расширения
  bool drop_short_upper_tokens = true;
  std::size_t short_upper_token_max_length = 3;

  /// @brief Отбрасывать длинные hex-like токены без расширения
  bool drop_hex_like_tokens = true;
  std::size_t hex_like_min_length = 16;

  /// @brief Отбрасывать длинные upper-alnum токены без расширения
  bool drop_upper_alnum_tokens = true;
  std::size_t upper_alnum_min_length = 8;

  /// @brief Включить правило prefetch_missing_but_other_artifacts_present
  bool tamper_rule_prefetch_missing_enabled = true;
  /// @brief Требовать, чтобы строка выглядела как образ процесса (`*.exe/...`)
  bool tamper_rule_prefetch_missing_require_process_image = true;
  /// @brief Источники runtime-доказательств для правила отсутствующего Prefetch
  std::vector<std::string> tamper_prefetch_missing_runtime_sources = {
      "EventLog", "UserAssist", "RunMRU", "FeatureUsage", "BAM",
      "DAM", "JumpList", "LNKRecent", "RecentApps", "TaskScheduler",
      "IFEO", "WER", "Timeline", "BITS", "WMIRepository", "WindowsSearch",
      "SRUM"};

  /// @brief Включить правило amcache_deleted_trace
  bool tamper_rule_amcache_deleted_trace_enabled = true;

  /// @brief Включить правило registry_inconsistency
  bool tamper_rule_registry_inconsistency_enabled = true;
  /// @brief Источники, которые считаются "только реестровыми"
  std::vector<std::string> tamper_registry_only_sources = {
      "RunMRU", "UserAssist", "BAM", "DAM", "ShimCache"};
  /// @brief Сильные источники корреляции (не только реестр)
  std::vector<std::string> tamper_registry_strong_sources = {
      "Prefetch", "Amcache", "EventLog", "SRUM"};
};

/// @class CSVExporter
/// @brief Класс для экспорта результатов анализа Windows в CSV формат
/// @details Предоставляет статический метод для экспорта данных о процессах,
/// автозагрузке и сетевых подключениях в структурированный CSV файл.
/// Поддерживает русскоязычные заголовки и форматирование данных
class CSVExporter {
 public:
  /// @brief Экспортирует данные анализа в CSV файл
  /// @param[in] output_path Путь для сохранения CSV файла
  /// @param[in] autorun_entries Список записей автозагрузки
  /// @param[in] process_data Данные о процессах (путь, хэш, время запусков)
  /// @param[in] network_connections Список сетевых подключений
  /// @param[in] amcache_entries Список записей из Amcache (версия, publisher,
  /// пути, хэши)
  /// @throw CsvExportException В случае ошибок экспорта
  /// @throw FileOpenException Если не удалось открыть файл для записи
  /// @throw DataFormatException При обнаружении некорректных данных
  /// @details Формат CSV:
  ///    - Имя исполняемого файла
  ///    - Набор обнаруженных путей
  ///    - Хэш исполняемого файла
  ///    - Времена запуска (разделенные точкой с запятой)
  ///    - Первое/последнее наблюдение (UTC)
  ///    - Таймлайн артефактов
  ///    - Источники восстановления (RecoveredFrom)
  ///    - Контекст пользователя и прав (Users/UserSIDs/LogonIDs/LogonTypes,
  ///      ElevationType/ElevatedToken/IntegrityLevel/Privileges)
  ///    - Статус автозагрузки (Да/Нет)
  ///    - Следы удаления файла в Amcache (Да/Нет)
  ///    - Версия ПО
  ///    - Сетевые подключения + поля сетевого контекста
  ///      (NetworkEventIDs/NetworkTimestamps/NetworkProcessIDs/
  ///       NetworkApplications/NetworkDirections/NetworkActions)
  ///    - Количество запусков
  ///    - Источники доказательств (EvidenceSources)
  ///    - Флаги подозрительности (TamperFlags)
  /// @note Все строковые значения экранируются двойными кавычками
  /// @note Временные метки форматируются в читаемый вид (YYYY-MM-DD HH:MM:SS)
  /// @note Для отсутствующих данных используется "N/A"
  static void exportToCSV(
      const std::string& output_path,
      const std::vector<AutorunEntry>& autorun_entries,
      const std::map<std::string, ProcessInfo>& process_data,
      const std::vector<NetworkConnection>& network_connections,
      const std::vector<AmcacheEntry>& amcache_entries,
      const CSVExportOptions& options = CSVExportOptions{});
};

}
