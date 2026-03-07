/// @file eventlog_analyzer.hpp
/// @brief Анализатор журналов событий Windows

#pragma once

#include <map>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/event_logs/ieventlog_collector.hpp"
#include "infra/config/config.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"

namespace WindowsDiskAnalysis {

/// @struct EventLogConfig
/// @brief Конфигурация параметров для анализа журналов событий
struct EventLogConfig {
  std::vector<std::string> log_paths;       ///< Пути к файлам журналов событий
  std::vector<uint32_t> process_event_ids;  ///< ID событий о процессах
  std::vector<uint32_t>
      network_event_ids;  ///< ID событий о сетевых подключениях
};

/// @class EventLogAnalyzer
/// @brief Анализатор журналов событий Windows
class EventLogAnalyzer final : public IEventLogCollector {
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
  /// @throws ParsingException При ошибках открытия или чтения журналов
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data,
               std::vector<NetworkConnection>& network_connections) override;

 private:
  /// @brief Загружает конфигурацию из INI-файла
  /// @param ini_path Путь к конфигурационному файлу
  void loadConfigurations(const std::string& ini_path);

  /// @brief Определяет парсер по расширению файла журнала
  /// @param file_path Путь к файлу журнала
  /// @return Указатель на соответствующий парсер
  [[nodiscard]] EventLogAnalysis::IEventLogParser* getParserForFile(
      const std::string& file_path) const;

  /// @brief Загружает параметры производительности из секции `[Performance]`.
  /// @param config Конфиг приложения.
  void loadPerformanceOptions(const Config& config);

  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evt_parser_;  ///< Парсер для EVT
  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evtx_parser_;  ///< Парсер для EVTX
  std::map<std::string, EventLogConfig>
      configs_;             ///< Конфигурации для версий ОС
  std::string os_version_;  ///< Целевая версия ОС
  bool enable_parallel_eventlog_ = false;
  std::size_t worker_threads_ =
      std::max<std::size_t>(1, std::thread::hardware_concurrency());
};

}  // namespace WindowsDiskAnalysis
