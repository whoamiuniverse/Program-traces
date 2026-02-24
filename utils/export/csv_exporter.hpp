/// @file csv_exporter.hpp
/// @brief Класс для экспорта результатов анализа Windows в CSV формат

#pragma once

#include <map>
#include <string>
#include <vector>

#include "../../core/analysis/program_analysis/data/analysis_data.hpp"
#include "../../core/exceptions/csv_export_exception.hpp"

namespace WindowsDiskAnalysis {

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
  /// @param amcache_entries
  /// @throw CsvExportException В случае ошибок экспорта
  /// @throw FileOpenException Если не удалось открыть файл для записи
  /// @throw DataFormatException При обнаружении некорректных данных
  /// @details Формат CSV:
  ///    - Исполняемый путь
  ///    - Хэш исполняемого файла
  ///    - Времена запуска (разделенные точкой с запятой)
  ///    - Статус автозагрузки (Да/Нет)
  ///    - Версия ПО
  ///    - Сетевые подключения
  ///    - Командная строка запуска
  ///    - Время создания файла
  ///    - Время последнего изменения
  ///    - Количество запусков
  /// @note Все строковые значения экранируются двойными кавычками
  /// @note Временные метки форматируются в читаемый вид (YYYY-MM-DD HH:MM:SS)
  /// @note Для отсутствующих данных используется "N/A"
  static void exportToCSV(
      const std::string& output_path,
      const std::vector<AutorunEntry>& autorun_entries,
      const std::map<std::string, ProcessInfo>& process_data,
      const std::vector<NetworkConnection>& network_connections,
      const std::vector<AmcacheEntry>& amcache_entries);
};

}
