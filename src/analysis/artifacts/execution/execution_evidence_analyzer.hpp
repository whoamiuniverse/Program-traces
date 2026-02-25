/// @file execution_evidence_analyzer.hpp
/// @brief Анализатор дополнительных источников исполнения процессов

#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "parsers/registry/parser/iparser.hpp"

namespace WindowsDiskAnalysis {

/// @struct ExecutionEvidenceConfig
/// @brief Конфигурация расширенных источников исполнения
struct ExecutionEvidenceConfig {
  bool enable_shimcache = true;
  bool enable_userassist = true;
  bool enable_runmru = true;
  bool enable_feature_usage = true;
  bool enable_recent_apps = true;
  bool enable_bam_dam = true;
  bool enable_jump_lists = true;
  bool enable_lnk_recent = true;
  bool enable_task_scheduler = true;
  bool enable_wer = true;
  bool enable_ifeo = true;
  bool enable_timeline = true;
  bool enable_bits = true;
  bool enable_wmi_repository = true;
  bool enable_windows_search = true;
  bool enable_windows_search_native_parser = true;
  bool windows_search_fallback_to_binary_on_native_failure = true;
  bool enable_srum = true;
  bool enable_srum_native_parser = true;
  bool srum_fallback_to_binary_on_native_failure = true;
  bool enable_security_log_tamper_check = true;

  std::size_t binary_scan_max_mb = 64;
  std::size_t max_candidates_per_source = 2000;
  std::size_t srum_native_max_records_per_table = 25000;
  std::size_t windows_search_native_max_records_per_table = 25000;

  std::string userassist_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist";
  std::string runmru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU";
  std::string feature_usage_app_switched_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "AppSwitched";
  std::string feature_usage_show_jumpview_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "ShowJumpView";
  std::string recent_apps_root_key =
      "Software/Microsoft/Windows/CurrentVersion/Search/RecentApps";
  std::string shimcache_value_path =
      "CurrentControlSet/Control/Session Manager/AppCompatCache/"
      "AppCompatCache";
  std::string bam_root_path = "CurrentControlSet/Services/bam/State/UserSettings";
  std::string dam_root_path = "CurrentControlSet/Services/dam/State/UserSettings";

  std::string recent_lnk_suffix = "AppData/Roaming/Microsoft/Windows/Recent";
  std::string jump_auto_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations";
  std::string jump_custom_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations";
  std::string task_scheduler_root_path = "Windows/System32/Tasks";
  std::string task_cache_tasks_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks";
  std::string ifeo_root_key =
      "Microsoft/Windows NT/CurrentVersion/Image File Execution Options";
  std::string wer_programdata_path = "ProgramData/Microsoft/Windows/WER";
  std::string wer_user_suffix = "AppData/Local/Microsoft/Windows/WER";
  std::string timeline_root_suffix =
      "AppData/Local/ConnectedDevicesPlatform";
  std::string bits_downloader_path = "ProgramData/Microsoft/Network/Downloader";
  std::string wmi_repository_path = "Windows/System32/wbem/Repository";
  std::string windows_search_path =
      "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb";
  std::vector<std::string> windows_search_table_allowlist;
  std::string srum_path = "Windows/System32/sru/SRUDB.dat";
  std::string security_log_path = "Windows/System32/winevt/Logs/Security.evtx";
  std::vector<std::string> srum_table_allowlist;
};

/// @class ExecutionEvidenceAnalyzer
/// @brief Собирает дополнительные источники запуска помимо Prefetch/Amcache
class ExecutionEvidenceAnalyzer {
 public:
  ExecutionEvidenceAnalyzer(
      std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
      std::string os_version, std::string ini_path);

  /// @brief Обогащает карту процессов источниками исполнения и таймлайном
  /// @param disk_root Корень Windows-раздела
  /// @param process_data Агрегированные данные процессов (изменяются)
  /// @param global_tamper_flags Глобальные tamper-флаги (дополняются)
  void collect(const std::string& disk_root,
               std::map<std::string, ProcessInfo>& process_data,
               std::vector<std::string>& global_tamper_flags);

 private:
  /// @brief Загружает параметры секции `[ExecutionArtifacts]` из config.ini.
  void loadConfiguration();

  /// @brief Определяет абсолютный путь к SOFTWARE hive для текущей версии ОС.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @return Путь к SOFTWARE hive или пустая строка.
  std::string resolveSoftwareHivePath(const std::string& disk_root) const;
  /// @brief Определяет абсолютный путь к SYSTEM hive для текущей версии ОС.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @return Путь к SYSTEM hive или пустая строка.
  std::string resolveSystemHivePath(const std::string& disk_root) const;

  /// @brief Этап реестровых источников исполнения.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param software_hive_path Путь к SOFTWARE hive.
  /// @param system_hive_path Путь к SYSTEM hive.
  /// @param process_data Агрегированные данные процессов.
  void collectRegistryArtifacts(
      const std::string& disk_root, const std::string& software_hive_path,
      const std::string& system_hive_path,
      std::map<std::string, ProcessInfo>& process_data);
  /// @brief Этап файловых источников исполнения.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectFilesystemArtifacts(const std::string& disk_root,
                                 std::map<std::string, ProcessInfo>& process_data);
  /// @brief Этап ESE/бинарных БД источников исполнения.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectDatabaseArtifacts(const std::string& disk_root,
                                std::map<std::string, ProcessInfo>& process_data);
  /// @brief Этап tamper-проверок, не привязанных к конкретному процессу.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param global_tamper_flags Глобальные tamper-флаги.
  void collectGlobalTamperSignals(const std::string& disk_root,
                                  std::vector<std::string>& global_tamper_flags);

  /// @brief Извлекает структурированные и fallback-записи ShimCache.
  /// @param system_hive_path Путь к SYSTEM hive.
  /// @param process_data Агрегированные данные процессов.
  void collectShimCache(const std::string& system_hive_path,
                        std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает сведения о выполнении из веток BAM/DAM.
  /// @param system_hive_path Путь к SYSTEM hive.
  /// @param process_data Агрегированные данные процессов.
  void collectBamDam(const std::string& system_hive_path,
                     std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает UserAssist/RunMRU из пользовательских hive.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectUserAssistAndRunMru(
      const std::string& disk_root,
      std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты FeatureUsage.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectFeatureUsage(const std::string& disk_root,
                           std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты RecentApps.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectRecentApps(const std::string& disk_root,
                         std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты из LNK Recent.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectLnkRecent(const std::string& disk_root,
                        std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты Jump Lists.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectJumpLists(const std::string& disk_root,
                        std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты Task Scheduler.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param software_hive_path Путь к SOFTWARE hive.
  /// @param process_data Агрегированные данные процессов.
  void collectTaskScheduler(const std::string& disk_root,
                            const std::string& software_hive_path,
                            std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты IFEO.
  /// @param software_hive_path Путь к SOFTWARE hive.
  /// @param process_data Агрегированные данные процессов.
  void collectIfeo(const std::string& software_hive_path,
                   std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты WER.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectWerReports(const std::string& disk_root,
                         std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты Activity Timeline.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectTimeline(const std::string& disk_root,
                       std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты BITS Downloader.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectBitsQueue(const std::string& disk_root,
                        std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты WMI Repository.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectWmiRepository(const std::string& disk_root,
                            std::map<std::string, ProcessInfo>& process_data);
  /// @brief Извлекает артефакты Windows Search (native/fallback).
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectWindowsSearch(const std::string& disk_root,
                            std::map<std::string, ProcessInfo>& process_data);
  /// @brief Нативно читает Windows.edb через libesedb.
  /// @param windows_search_path Путь к `Windows.edb`.
  /// @param process_data Агрегированные данные процессов.
  /// @return Количество добавленных кандидатов.
  std::size_t collectWindowsSearchNative(
      const std::filesystem::path& windows_search_path,
      std::map<std::string, ProcessInfo>& process_data);
  /// @brief Fallback бинарного извлечения для Windows Search.
  /// @param windows_search_path Путь к `Windows.edb`.
  /// @param process_data Агрегированные данные процессов.
  /// @return Количество добавленных кандидатов.
  std::size_t collectWindowsSearchBinaryFallback(
      const std::filesystem::path& windows_search_path,
      std::map<std::string, ProcessInfo>& process_data) const;
  /// @brief Извлекает артефакты SRUM (native/fallback).
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param process_data Агрегированные данные процессов.
  void collectSrum(const std::string& disk_root,
                   std::map<std::string, ProcessInfo>& process_data);
  /// @brief Нативно читает `SRUDB.dat` через libesedb.
  /// @param srum_path Путь к `SRUDB.dat`.
  /// @param process_data Агрегированные данные процессов.
  /// @return Количество добавленных кандидатов.
  std::size_t collectSrumNative(
      const std::filesystem::path& srum_path,
      std::map<std::string, ProcessInfo>& process_data);
  /// @brief Fallback бинарного извлечения для SRUM.
  /// @param srum_path Путь к `SRUDB.dat`.
  /// @param process_data Агрегированные данные процессов.
  /// @return Количество добавленных кандидатов.
  std::size_t collectSrumBinaryFallback(
      const std::filesystem::path& srum_path,
      std::map<std::string, ProcessInfo>& process_data) const;
  /// @brief Проверяет признаки очистки Security.evtx.
  /// @param disk_root Корень смонтированного Windows-раздела.
  /// @param global_tamper_flags Глобальные tamper-флаги.
  void detectSecurityLogTampering(const std::string& disk_root,
                                  std::vector<std::string>& global_tamper_flags);

  std::unique_ptr<RegistryAnalysis::IRegistryParser> parser_;
  std::string os_version_;
  std::string ini_path_;
  ExecutionEvidenceConfig config_;
};

}  // namespace WindowsDiskAnalysis
