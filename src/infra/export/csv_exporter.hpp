/// @file csv_exporter.hpp
/// @brief Класс для экспорта результатов анализа Windows в CSV формат

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "errors/csv_export_exception.hpp"

namespace WindowsDiskAnalysis {

/// @struct CSVExportOptions
/// @brief Параметры экспорта CSV.
struct CSVExportOptions {
  bool export_recovery_csv = false;  ///< Создавать дополнительный recovery CSV.
  std::string recovery_output_path;  ///< Явный путь recovery CSV (опционально).
};

/// @class CSVExporter
/// @brief Класс для экспорта результатов анализа Windows в CSV формат
/// @details Экспортирует extraction/recovery артефакты в единый record-level CSV
/// со стабильным набором колонок.
class CSVExporter {
 public:
  /// @brief Экспортирует данные анализа в CSV файл
  /// @param[in] output_path Путь для сохранения CSV файла
  /// @param[in] autorun_entries Список записей автозагрузки
  /// @param[in] process_data Данные о процессах (путь, хэш, время запусков)
  /// @param[in] network_connections Список сетевых подключений
  /// @param[in] amcache_entries Список записей из Amcache (версия, publisher,
  /// пути, хэши)
  /// @param[in] recovery_evidence Список recovery-свидетельств из USN/VSS/...
  /// @throw CsvExportException В случае ошибок экспорта
  /// @throw FileOpenException Если не удалось открыть файл для записи
  /// @throw DataFormatException При обнаружении некорректных данных
  /// @details Основной CSV содержит унифицированные колонки:
  ///    `record_id;source;artifact_type;path_or_key;timestamp_utc;
  ///     is_recovered;recovered_from;host_hint;user_hint;raw_details`.
  ///    Дополнительно (по опции) может создаваться отдельный recovery CSV.
  /// @note Все строковые значения экранируются двойными кавычками
  /// @note Символы новой строки в полях заменяются пробелами
  static void exportToCSV(
      const std::string& output_path,
      const std::vector<AutorunEntry>& autorun_entries,
      const std::unordered_map<std::string, ProcessInfo>& process_data,
      const std::vector<NetworkConnection>& network_connections,
      const std::vector<AmcacheEntry>& amcache_entries,
      const std::vector<RecoveryEvidence>& recovery_evidence,
      const CSVExportOptions& options = {});
};

}
