/// @file csv_exporter.hpp
/// @brief Класс для экспорта результатов анализа Windows в CSV формат

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "errors/csv_export_exception.hpp"

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
  ///    - Сводка сетевых подключений процесса
  ///    - Отдельный network context блок
  ///      (NetworkTimelineArtifacts/NetworkContextSources/
  ///       NetworkProfiles/FirewallRules)
  ///    - Количество запусков
  ///    - Источники доказательств (EvidenceSources)
  ///    - Флаги подозрительности (TamperFlags)
  /// @note Все строковые значения экранируются двойными кавычками
  /// @note Временные метки форматируются в читаемый вид (YYYY-MM-DD HH:MM:SS)
  /// @note Для отсутствующих данных используется "N/A"
  static void exportToCSV(
      const std::string& output_path,
      const std::vector<AutorunEntry>& autorun_entries,
      const std::unordered_map<std::string, ProcessInfo>& process_data,
      const std::vector<NetworkConnection>& network_connections,
      const std::vector<AmcacheEntry>& amcache_entries,
      const std::vector<RecoveryEvidence>& recovery_evidence);
};

}
