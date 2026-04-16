/// @file execution_evidence_config.hpp
/// @brief Конфигурация модуля извлечения следов запуска ПО.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

/// @struct ExecutionEvidenceConfig
/// @brief Параметры анализа для целевого набора источников (11 артефактов).
/// @details Загружается из секции @c [ExecutionArtifacts] при запуске.
struct ExecutionEvidenceConfig {
  // ---- Общие лимиты ----
  std::size_t binary_scan_max_mb = 64;          ///< Лимит бинарного чтения (МБ).
  std::size_t max_candidates_per_source = 2000; ///< Лимит кандидатов на источник.
  std::size_t srum_native_max_records_per_table =
      25000;  ///< Лимит SRUM-записей на таблицу (native).

  // ---- Реестр ----
  std::string userassist_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist";
  std::string runmru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU";
  std::string shimcache_value_path =
      "CurrentControlSet/Control/Session Manager/AppCompatCache/"
      "AppCompatCache";
  std::string bam_root_path = "CurrentControlSet/Services/bam/State/UserSettings";
  std::string dam_root_path = "CurrentControlSet/Services/dam/State/UserSettings";
  std::string bam_legacy_root_path = "CurrentControlSet/Services/bam/UserSettings";
  std::string dam_legacy_root_path = "CurrentControlSet/Services/dam/UserSettings";
  std::string task_cache_tasks_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks";
  std::string task_cache_tree_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tree";

  // ---- Файловые источники ----
  std::string recent_lnk_suffix = "AppData/Roaming/Microsoft/Windows/Recent";
  std::string jump_auto_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations";
  std::string jump_custom_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations";
  std::string task_scheduler_root_path = "Windows/System32/Tasks";
  std::string srum_path = "Windows/System32/sru/SRUDB.dat";
  std::string ps_history_suffix =
      "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/"
      "ConsoleHost_history.txt";
  std::vector<std::string> srum_table_allowlist;  ///< Allowlist таблиц SRUM.
};

}  // namespace WindowsDiskAnalysis
