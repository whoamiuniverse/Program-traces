/// @file windows_disk_analyzer.hpp
/// @brief Оркестратор полного анализа подключённого диска Windows

#pragma once

#include <map>
#include <memory>
#include <vector>

#include "infra/config/config.hpp"
#include "infra/export/csv_exporter.hpp"
#include "amcache/amcache_analyzer.hpp"
#include "autorun/autorun_analyzer.hpp"
#include "event_logs/eventlog_analyzer.hpp"
#include "prefetch/prefetch_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class WindowsDiskAnalyzer
/// @brief Координирует запуск всех анализаторов артефактов и экспорт результата
class WindowsDiskAnalyzer {
 public:
  /// @brief Создаёт оркестратор анализа диска
  /// @param disk_root Корневой путь подключённого диска Windows
  /// @param config_path Путь к основному конфигурационному INI-файлу
  WindowsDiskAnalyzer(std::string disk_root,
                      const std::string& config_path);

  /// @brief Выполняет полный анализ и сохраняет итоговый CSV-отчёт
  /// @param output_path Путь к каталогу или файлу для результатов
  /// @throws ConfigException При ошибках загрузки конфигурации
  /// @throws OSDetectionException При ошибках определения версии ОС
  /// @throws ParsingException При ошибках разбора артефактов
  /// @throws CsvExportException При ошибках экспорта отчёта
  void analyze(const std::string& output_path);

 private:
  /// @brief Инициализирует внутренние анализаторы на основе версии ОС
  void initializeComponents();

  /// @brief Определяет версию Windows на подключённом диске
  void detectOSVersion();

  /// @brief Проверяет наличие hive-файлов из конфигурации в корне диска
  /// @param config Загруженная конфигурация
  /// @throws std::runtime_error Если ни один путь реестра не найден
  void validateRegistryHivePresence(const Config& config) const;

  /// @brief Проверяет наличие hive-файлов в указанном корне
  /// @param config Загруженная конфигурация
  /// @param disk_root Корень диска для проверки
  /// @param checked_paths Опциональный вывод проверенных путей
  /// @return true если найден хотя бы один hive-файл
  bool hasRegistryHivePresence(
      const Config& config, const std::string& disk_root,
      std::vector<std::string>* checked_paths = nullptr) const;

  /// @brief Пытается автоматически выбрать корректный Windows-том
  /// @param config Загруженная конфигурация
  /// @param initial_check_error Исходная ошибка проверки выбранного корня
  /// @return true если корень успешно переопределён
  bool tryAutoSelectWindowsRoot(const Config& config,
                                const std::string& initial_check_error);

  /// @brief Гарантирует наличие каталога для выхода
  /// @param path Путь к каталогу, который должен существовать
  /// @throws std::runtime_error Если каталог невозможно создать
  static void ensureDirectoryExists(const std::string& path);

  std::string disk_root_;    ///< Корневой путь подключённого диска
  std::string config_path_;  ///< Путь к конфигурационному файлу
  OSInfo os_info_;           ///< Определённая информация о версии ОС

  std::unique_ptr<AutorunAnalyzer>
      autorun_analyzer_;  ///< Анализатор записей автозапуска
  std::unique_ptr<PrefetchAnalyzer>
      prefetch_analyzer_;  ///< Анализатор Prefetch-артефактов
  std::unique_ptr<EventLogAnalyzer>
      eventlog_analyzer_;  ///< Анализатор журналов событий
  std::unique_ptr<AmcacheAnalyzer>
      amcache_analyzer_;  ///< Анализатор артефактов Amcache

  std::vector<AutorunEntry>
      autorun_entries_;  ///< Результаты анализа автозагрузки
  std::map<std::string, ProcessInfo>
      process_data_;  ///< Агрегированные сведения о процессах
  std::vector<NetworkConnection>
      network_connections_;  ///< Выявленные сетевые соединения
  std::vector<AmcacheEntry> amcache_entries_;  ///< Записи из Amcache
};

}
