/// @file eventlog_analyzer.hpp
/// @brief Анализатор журналов событий Windows

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../../../../parsers/event_log/evtx/parser/parser.hpp"
#include "../../os_detection/os_detection.hpp"
#include "../data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @brief Конфигурация параметров для анализа журналов событий
struct EventLogConfig {
  std::vector<std::string> log_paths;       ///< Пути к файлам журналов событий
  std::vector<uint32_t> process_event_ids;  ///< ID событий о процессах
  std::vector<uint32_t>
      network_event_ids;  ///< ID событий о сетевых подключениях
};

/// @brief Анализатор журналов событий Windows
class EventLogAnalyzer {
 public:
  /// @brief Конструктор анализатора
  /// @param evt_parser Парсер для формата EVT
  /// @param evtx_parser Парсер для формата EVTX
  /// @param os_version Версия целевой ОС
  /// @param ini_path Путь к конфигурационному файлу
  EventLogAnalyzer(
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
      std::string os_version, const std::string& ini_path);

  /// @brief Сбор данных из журналов событий
  /// @param disk_root Корневой путь анализируемого диска
  /// @param process_data Карта данных о процессах (заполняется)
  /// @param network_connections Вектор сетевых подключений (заполняется)
  void collect(const std::string& disk_root,
               std::map<std::string, ProcessInfo>& process_data,
               std::vector<NetworkConnection>& network_connections);

 private:
  /// @brief Загружает конфигурацию из INI-файла
  /// @param ini_path Путь к конфигурационному файлу
  void loadConfigurations(const std::string& ini_path);

  /// @brief Определяет парсер по расширению файла журнала
  /// @param file_path Путь к файлу журнала
  /// @return Указатель на соответствующий парсер
  [[nodiscard]] EventLogAnalysis::IEventLogParser* getParserForFile(
      const std::string& file_path) const;

  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evt_parser_;  ///< Парсер для EVT
  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evtx_parser_;  ///< Парсер для EVTX
  std::map<std::string, EventLogConfig>
      configs_;             ///< Конфигурации для версий ОС
  std::string os_version_;  ///< Целевая версия ОС
};

}