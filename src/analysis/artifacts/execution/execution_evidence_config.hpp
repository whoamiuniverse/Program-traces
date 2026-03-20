/// @file execution_evidence_config.hpp
/// @brief Configuration for extended process execution evidence sources.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

/// @struct ExecutionEvidenceConfig
/// @brief Holds all feature flags and path settings for the execution evidence analysis stage.
///
/// @details Loaded from the @c [ExecutionArtifacts] INI section at startup.
/// Each @c enable_X flag controls whether the corresponding collector runs.
/// Path fields contain relative paths from the disk root or registry key paths.
struct ExecutionEvidenceConfig {
  bool enable_shimcache = true;              ///< Enable ShimCache (AppCompatCache) collection.
  bool enable_userassist = true;             ///< Enable UserAssist collection from NTUSER.DAT.
  bool enable_runmru = true;                 ///< Enable RunMRU collection from NTUSER.DAT.
  bool enable_feature_usage = true;          ///< Enable FeatureUsage collection from NTUSER.DAT.
  bool enable_recent_apps = true;            ///< Enable RecentApps collection from NTUSER.DAT.
  bool enable_bam_dam = true;               ///< Enable BAM/DAM collection from SYSTEM hive.
  bool enable_services = true;              ///< Enable Windows Services collection from SYSTEM hive.
  bool enable_hosts_file = true;            ///< Enable hosts file scanning.
  bool enable_network_profiles = true;      ///< Enable NetworkList profile collection from SOFTWARE hive.
  bool enable_jump_lists = true;            ///< Enable Jump Lists artifact collection.
  bool enable_lnk_recent = true;            ///< Enable LNK file collection from Recent folders.
  bool enable_task_scheduler = true;        ///< Enable Task Scheduler artifact collection.
  bool enable_wer = true;                   ///< Enable Windows Error Reporting artifact collection.
  bool enable_ifeo = true;                  ///< Enable Image File Execution Options collection.
  bool enable_timeline = true;              ///< Enable Windows Timeline (ActivitiesCache.db) collection.
  bool enable_bits = true;                  ///< Enable BITS queue artifact collection.
  bool enable_wmi_repository = true;        ///< Enable WMI Repository artifact collection.
  bool enable_windows_search = true;        ///< Enable Windows Search (Windows.edb) collection.
  bool enable_windows_search_native_parser = true;  ///< Use native ESE parser for Windows Search.
  bool windows_search_fallback_to_binary_on_native_failure = true;  ///< Fall back to binary scan when native Windows Search parsing fails.
  bool enable_srum = true;                  ///< Enable SRUM (SRUDB.dat) collection.
  bool enable_srum_native_parser = true;    ///< Use native ESE parser for SRUM.
  bool srum_fallback_to_binary_on_native_failure = true;  ///< Fall back to binary scan when native SRUM parsing fails.
  bool enable_security_log_tamper_check = true;        ///< Enable Security log tamper detection (Event ID 1102).
  bool enable_system_log_tamper_check = true;          ///< Enable System log tamper detection (Event ID 104).
  bool enable_registry_state_tamper_check = true;      ///< Enable registry-state tamper checks (prefetch disabled, EventLog service stopped).
  bool enable_artifact_presence_tamper_check = true;   ///< Enable artifact presence checks (Amcache, USN, VSS).
  bool enable_muicache = true;              ///< Enable MuiCache collection from NTUSER.DAT.
  bool enable_appcompat_flags = true;       ///< Enable AppCompatFlags collection from SOFTWARE and NTUSER.DAT.
  bool enable_typed_paths = true;           ///< Enable TypedPaths collection from NTUSER.DAT.
  bool enable_last_visited_mru = true;      ///< Enable LastVisitedPidlMRU collection from NTUSER.DAT.
  bool enable_open_save_mru = true;         ///< Enable OpenSavePidlMRU collection from NTUSER.DAT.
  bool enable_ps_history = true;            ///< Enable PowerShell console history collection.

  std::size_t binary_scan_max_mb = 64;               ///< Maximum bytes (in MB) for binary fallback scans.
  std::size_t max_candidates_per_source = 2000;      ///< Maximum candidates extracted per source.
  std::size_t srum_native_max_records_per_table = 25000;            ///< Maximum SRUM records per table in native mode.
  std::size_t windows_search_native_max_records_per_table = 25000;  ///< Maximum Windows Search records per table in native mode.

  std::string userassist_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist";  ///< Registry key for UserAssist.
  std::string runmru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU";  ///< Registry key for RunMRU.
  std::string feature_usage_app_switched_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "AppSwitched";  ///< Registry key for FeatureUsage AppSwitched.
  std::string feature_usage_show_jumpview_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "ShowJumpView";  ///< Registry key for FeatureUsage ShowJumpView.
  std::string feature_usage_app_badge_updated_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "AppBadgeUpdated";  ///< Registry key for FeatureUsage AppBadgeUpdated.
  std::string recent_apps_root_key =
      "Software/Microsoft/Windows/CurrentVersion/Search/RecentApps";  ///< Registry key for RecentApps root.
  std::string recent_apps_recent_items_suffix = "RecentItems";  ///< Subkey suffix for RecentApps items.
  std::string shimcache_value_path =
      "CurrentControlSet/Control/Session Manager/AppCompatCache/"
      "AppCompatCache";  ///< Registry value path for ShimCache binary data.
  std::string bam_root_path = "CurrentControlSet/Services/bam/State/UserSettings";   ///< Registry path for BAM (Windows 10 1809+).
  std::string dam_root_path = "CurrentControlSet/Services/dam/State/UserSettings";   ///< Registry path for DAM (Windows 10 1809+).
  std::string bam_legacy_root_path = "CurrentControlSet/Services/bam/UserSettings";  ///< Registry path for BAM (legacy builds).
  std::string dam_legacy_root_path = "CurrentControlSet/Services/dam/UserSettings";  ///< Registry path for DAM (legacy builds).
  std::string services_root_path = "CurrentControlSet/Services";  ///< Registry root path for Windows Services.
  std::string network_profiles_root_key =
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles";  ///< Registry key for NetworkList profiles.
  std::vector<std::string> network_signature_roots = {
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Signatures/Managed",
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Signatures/Unmanaged"};  ///< Registry paths for NetworkList signatures.

  std::string recent_lnk_suffix = "AppData/Roaming/Microsoft/Windows/Recent";  ///< User-relative path to the Recent LNK directory.
  std::string jump_auto_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations";  ///< User-relative path to AutomaticDestinations Jump Lists.
  std::string jump_custom_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations";  ///< User-relative path to CustomDestinations Jump Lists.
  std::string task_scheduler_root_path = "Windows/System32/Tasks";  ///< Disk-relative path to the Task Scheduler task directory.
  std::string task_cache_tasks_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks";  ///< Registry key for TaskCache tasks.
  std::string task_cache_tree_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tree";  ///< Registry key for TaskCache task tree.
  std::string ifeo_root_key =
      "Microsoft/Windows NT/CurrentVersion/Image File Execution Options";  ///< Registry root key for IFEO (64-bit).
  std::string ifeo_wow6432_root_key =
      "Wow6432Node/Microsoft/Windows NT/CurrentVersion/Image File Execution "
      "Options";  ///< Registry root key for IFEO (32-bit via WoW64).
  std::string wer_programdata_path = "ProgramData/Microsoft/Windows/WER";  ///< System-wide WER report directory.
  std::string wer_user_suffix = "AppData/Local/Microsoft/Windows/WER";     ///< User-relative WER report directory suffix.
  std::string timeline_root_suffix =
      "AppData/Local/ConnectedDevicesPlatform";  ///< User-relative path to the Windows Timeline root.
  std::string bits_downloader_path = "ProgramData/Microsoft/Network/Downloader";  ///< Disk-relative path to the BITS queue directory.
  std::string hosts_file_path = "Windows/System32/drivers/etc/hosts";  ///< Disk-relative path to the hosts file.
  std::string wmi_repository_path = "Windows/System32/wbem/Repository";  ///< Disk-relative path to the WMI repository.
  std::string windows_search_path =
      "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb";  ///< Disk-relative path to the Windows Search ESE database.
  std::vector<std::string> windows_search_table_allowlist;  ///< Allowlist of ESE table names for Windows Search; empty means all tables.
  std::string srum_path = "Windows/System32/sru/SRUDB.dat";  ///< Disk-relative path to the SRUM database.
  std::string security_log_path = "Windows/System32/winevt/Logs/Security.evtx";  ///< Disk-relative path to the Security Event Log.
  std::string system_log_path = "Windows/System32/winevt/Logs/System.evtx";      ///< Disk-relative path to the System Event Log.
  std::vector<std::string> srum_table_allowlist;  ///< Allowlist of ESE table names for SRUM; empty means all tables.

  std::string muicache_key =
      "Software/Classes/Local Settings/Software/Microsoft/Windows/Shell/"
      "MuiCache";  ///< Registry key for MuiCache entries.
  std::string appcompat_layers_key =
      "Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/Layers";  ///< Registry key for AppCompatFlags/Layers.
  std::string appcompat_assist_key =
      "Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/"
      "Compatibility Assistant/Store";  ///< Registry key for AppCompatFlags Compatibility Assistant store.
  std::string typed_paths_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths";  ///< Registry key for TypedPaths (address bar history).
  std::string last_visited_mru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/"
      "LastVisitedPidlMRU";  ///< Registry key for LastVisitedPidlMRU.
  std::string open_save_mru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/"
      "OpenSavePidlMRU";  ///< Registry key for OpenSavePidlMRU.
  std::string ps_history_suffix =
      "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/"
      "ConsoleHost_history.txt";  ///< User-relative path to the PSReadLine console history file.
};

}  // namespace WindowsDiskAnalysis
