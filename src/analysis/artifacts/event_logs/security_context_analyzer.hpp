/// @file security_context_analyzer.hpp
/// @brief Анализатор Security Event Log для контекста запуска процесса

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "parsers/event_log/interfaces/iparser.hpp"

namespace WindowsDiskAnalysis {

/// @struct SecurityContextConfig
/// @brief Конфигурация анализа Security Event Log.
struct SecurityContextConfig {
  bool enabled = true;  ///< Включён ли анализ контекста безопасности.
  std::string security_log_path =
      "Windows/System32/winevt/Logs/Security.evtx";  ///< Путь к Security log.
  std::vector<uint32_t>
      process_create_event_ids = {4688};  ///< События создания процесса.
  std::vector<uint32_t> logon_event_ids = {4624};  ///< События входа в систему.
  std::vector<uint32_t>
      privilege_event_ids = {4672};  ///< События выдачи привилегий.
  uint32_t logon_correlation_window_seconds =
      43200;  ///< Окно корреляции 4688<->4624/4672.
  uint32_t pid_correlation_window_seconds =
      3600;  ///< Окно корреляции через PID с сетевыми событиями.
};

/// @class SecurityContextAnalyzer
/// @brief Извлекает "кто запускал и с какими правами" из Security Event Log.
///
/// @details Анализатор читает Security.evtx (или Security.evt), выделяет события
/// `4688`, `4624`, `4672` и коррелирует их по `LogonId`, времени и PID.
class SecurityContextAnalyzer {
 public:
  /// @brief Создаёт анализатор контекста безопасности.
  /// @param evt_parser Парсер событий формата `.evt`.
  /// @param evtx_parser Парсер событий формата `.evtx`.
  /// @param os_version Версия ОС (из INI-идентификатора), используется в логах.
  /// @param ini_path Путь к `config.ini`.
  SecurityContextAnalyzer(
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
      std::string os_version, const std::string& ini_path);

  /// @brief Обогащает `process_data` контекстом безопасности из Security log.
  /// @param disk_root Корневой путь смонтированного Windows-тома.
  /// @param process_data Агрегированная карта процессов (обновляется на месте).
  /// @param network_connections Сетевые события для PID-восстановления процесса.
  void collect(const std::string& disk_root,
               std::map<std::string, ProcessInfo>& process_data,
               const std::vector<NetworkConnection>& network_connections);

 private:
  /// @brief Загружает конфигурацию SecurityContext из INI.
  /// @param ini_path Путь к `config.ini`.
  void loadConfig(const std::string& ini_path);

  /// @brief Возвращает путь к Security log с учётом корня диска.
  /// @param disk_root Корень смонтированного Windows-тома.
  /// @return Полный путь к Security log или пустая строка при ошибке.
  [[nodiscard]] std::string resolveSecurityLogPath(
      const std::string& disk_root) const;

  /// @brief Выбирает парсер по расширению файла журнала.
  /// @param file_path Путь к `.evt/.evtx` файлу.
  /// @return Указатель на подходящий парсер либо `nullptr`.
  [[nodiscard]] EventLogAnalysis::IEventLogParser* getParserForFile(
      const std::string& file_path) const;

  std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser_;
  std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser_;
  std::string os_version_;
  SecurityContextConfig config_;
};

}  // namespace WindowsDiskAnalysis

