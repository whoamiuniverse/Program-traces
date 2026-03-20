/// @file windows_disk_analyzer.hpp
/// @brief Оркестратор полного анализа подключённого диска Windows

#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/amcache/amcache_analyzer.hpp"
#include "analysis/artifacts/autorun/autorun_analyzer.hpp"
#include "analysis/artifacts/event_logs/ieventlog_collector.hpp"
#include "analysis/artifacts/execution/execution_evidence_analyzer.hpp"
#include "analysis/artifacts/prefetch/prefetch_analyzer.hpp"
#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"
#include "analysis/os/os_info.hpp"
#include "errors/disk_analyzer_exception.hpp"
#include "infra/config/config.hpp"
#include "infra/export/csv_exporter.hpp"

namespace WindowsDiskAnalysis {

/// @class WindowsDiskAnalyzer
/// @brief Координирует запуск всех анализаторов артефактов и экспорт результата
class WindowsDiskAnalyzer {
 public:
  /// @struct AnalyzeOutputOptions
  /// @brief Параметры формирования выходных файлов анализа.
  struct AnalyzeOutputOptions {
    bool export_recovery_csv = false;  ///< Создавать `<output_base>_recovery.csv`.
    std::string recovery_output_path;  ///< Явный путь recovery CSV (опционально).
  };

  /// @brief Создаёт оркестратор анализа диска
  /// @param disk_root         Корневой путь подключённого диска Windows
  /// @param config_path       Путь к основному конфигурационному INI-файлу
  /// @param cli_image_path    Если непустой — передаётся в SignatureScanner как
  ///                          переопределение [Recovery]/SignatureScanPath из конфига.
  WindowsDiskAnalyzer(std::string disk_root, const std::string& config_path,
                      std::string cli_image_path = {});

  /// @brief Выполняет полный анализ и сохраняет итоговый CSV-отчёт
  /// @param output_path Путь к каталогу или файлу для результатов
  /// @param options Дополнительные параметры выходных файлов.
  /// @throws ConfigException           При ошибках загрузки конфигурации
  /// @throws OSDetectionException      При ошибках определения версии ОС
  /// @throws DiskAnalyzerException     При ошибках выбора/валидации диска
  /// @throws ParsingException          При ошибках разбора артефактов
  /// @throws CsvExportException        При ошибках экспорта отчёта
  void analyze(const std::string& output_path,
               const AnalyzeOutputOptions& options);

 private:
  // ------------------------------------------------------------------ types

  /// @struct ArtifactDebugOptions
  /// @brief Флаги подробного debug-логирования по этапам анализа
  struct ArtifactDebugOptions {
    bool os_detection = true;  ///< Логирование этапа определения ОС.
    bool autorun      = true;  ///< Логирование анализа автозагрузки.
    bool prefetch     = true;  ///< Логирование анализа Prefetch.
    bool eventlog     = true;  ///< Логирование анализа EventLog.
    bool amcache      = true;  ///< Логирование анализа Amcache.
    bool execution    = true;  ///< Логирование расширенных execution-артефактов.
    bool recovery     = true;  ///< Логирование recovery-анализаторов.
  };

  /// @struct PerformanceOptions
  /// @brief Настройки производительности и параллельного выполнения этапов
  struct PerformanceOptions {
    bool        enable_parallel_stages = false;  ///< Параллельный запуск recovery-секций
    std::size_t worker_threads         = 4;      ///< Число worker-потоков
    std::size_t max_io_workers         = 4;      ///< Ограничение I/O-bound workers
  };

  /// @struct TamperOptions
  /// @brief Настройки правил подозрительных признаков.
  struct TamperOptions {
    bool enable_prefetch_missing_rule = true;  ///< Включает правило `PrefetchMissingOnDisk`.
    bool prefetch_missing_require_process_image =
        true;  ///< Требует наличие process-image для срабатывания Prefetch-правила.
    std::vector<std::string> runtime_sources = {
        "EventLog",      "UserAssist",  "RunMRU",       "FeatureUsage",
        "BAM",           "DAM",         "JumpList",     "LNKRecent",
        "RecentApps",    "TaskScheduler","IFEO",         "WER",
        "Timeline",      "BITS",        "WMIRepository","WindowsSearch",
        "SRUM",          "ShimCache"};  ///< Источники runtime-следов для rule engine.
  };

  /// @struct NamedRecoveryAnalyzer
  /// @brief Recovery-анализатор с человеко-читаемой меткой для логирования.
  ///
  /// Использование вектора `NamedRecoveryAnalyzer` вместо пяти отдельных
  /// `unique_ptr`-полей соответствует принципу OCP: новый анализатор
  /// добавляется одной строкой в `initializeComponents()` без изменений
  /// заголовка, `runRecoveryStage()` или `resetAnalysisState()`.
  struct NamedRecoveryAnalyzer {
    std::string                       label;     ///< Метка для логов ("USN", "VSS", …)
    std::unique_ptr<IRecoveryAnalyzer> analyzer;  ///< Реализация анализатора
  };

  // --------------------------------------------------------------- helpers

  /// @brief Инициализирует внутренние анализаторы на основе версии ОС
  void initializeComponents();

  /// @brief Определяет версию Windows на подключённом диске
  void detectOSVersion();

  /// @brief Проверяет наличие hive-файлов из конфигурации в корне диска
  void validateRegistryHivePresence(const Config& config) const;

  /// @brief Проверяет наличие hive-файлов в указанном корне
  bool hasRegistryHivePresence(
      const Config& config, const std::string& disk_root,
      std::vector<std::string>* checked_paths  = nullptr,
      std::vector<std::string>* checked_errors = nullptr) const;

  /// @brief Пытается автоматически выбрать корректный Windows-том
  bool tryAutoSelectWindowsRoot(const Config& config,
                                const std::string& initial_check_error);

  /// @brief Гарантирует наличие каталога для выхода
  static void ensureDirectoryExists(const std::string& path);

  /// @brief Загружает настройки [Logging] для debug-логов по артефактам
  void loadLoggingOptions(const Config& config);

  /// @brief Загружает настройки [Performance] для параллельного выполнения
  void loadPerformanceOptions(const Config& config);

  /// @brief Загружает настройки правил Tamper из `[TamperRules]`.
  void loadTamperOptions(const Config& config);

  /// @brief Очищает внутреннее состояние перед новым запуском анализа
  void resetAnalysisState();

  // -------------------------------------------------------- analysis stages

  /// @brief Этап 1: автозагрузка — мержит результат в `process_data_`
  void runAutorunStage();

  /// @brief Этап 2: Amcache — мержит результат в `process_data_`
  void runAmcacheStage();

  /// @brief Этап 3: Prefetch — мержит результат в `process_data_`
  void runPrefetchStage();

  /// @brief Этап 4: EventLog (все зарегистрированные collectors)
  void runEventLogStage();

  /// @brief Этап 5: доп. источники исполнения + network timeline merge
  void runExecutionStage();

  /// @brief Этап 6: recovery (все зарегистрированные анализаторы)
  void runRecoveryStage();

  /// @brief Применяет глобальные tamper-флаги ко всем процессам
  void applyGlobalTamperFlags();

  /// @brief Применяет локальные tamper-правила к агрегированным процессам.
  void applyTamperRules();

  /// @brief Экспортирует агрегированные данные в CSV
  void exportCsv(const std::string& output_path,
                 const AnalyzeOutputOptions& options);

  // -------------------------------------------------------------- state

  std::string disk_root_;        ///< Корневой путь подключённого диска
  std::string config_path_;      ///< Путь к конфигурационному файлу
  std::string cli_image_path_;   ///< Образ диска из CLI (override для SignatureScanner).
  OSInfo      os_info_;          ///< Определённая информация о версии ОС

  ArtifactDebugOptions debug_options_;       ///< Настройки debug-логирования
  PerformanceOptions   performance_options_; ///< Настройки производительности
  TamperOptions        tamper_options_;      ///< Настройки tamper-правил

  // ---------------------------------------------------------------- analyzers

  std::unique_ptr<AutorunAnalyzer>
      autorun_analyzer_;  ///< Анализатор автозагрузки.
  std::unique_ptr<PrefetchAnalyzer>
      prefetch_analyzer_;  ///< Анализатор Prefetch.
  std::unique_ptr<AmcacheAnalyzer>
      amcache_analyzer_;  ///< Анализатор Amcache.
  std::unique_ptr<ExecutionEvidenceAnalyzer>
      execution_evidence_analyzer_;  ///< Анализатор execution-артефактов.

  /// Все collectors event-log (EventLogAnalyzer, SecurityContextAnalyzer, …)
  /// зарегистрированы через интерфейс IEventLogCollector (DIP / OCP).
  std::vector<std::unique_ptr<IEventLogCollector>> eventlog_collectors_;

  /// Recovery-анализаторы с метками для логирования (OCP / DIP).
  /// Добавление нового анализатора — одна строка в `initializeComponents()`.
  std::vector<NamedRecoveryAnalyzer> recovery_analyzers_;

  // -------------------------------------------------------------- results

  std::vector<AutorunEntry> autorun_entries_;  ///< Собранные записи автозапуска.
  std::unordered_map<std::string, ProcessInfo>
      process_data_;  ///< Агрегированная карта процессов по имени.
  std::vector<NetworkConnection>
      network_connections_;  ///< Сетевые события процесса.
  std::vector<AmcacheEntry> amcache_entries_;  ///< Собранные записи Amcache.
  std::vector<std::string>
      global_tamper_flags_;  ///< Глобальные tamper-флаги из execution-этапа.
  std::vector<RecoveryEvidence>           recovery_evidence_;  ///< Общий пул recovery
};

}  // namespace WindowsDiskAnalysis
