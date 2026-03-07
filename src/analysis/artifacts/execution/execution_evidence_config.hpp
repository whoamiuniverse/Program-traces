/// @file execution_evidence_config.hpp
/// @brief Конфигурация расширенных источников исполнения процессов.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

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
  bool enable_services = true;
  bool enable_hosts_file = true;
  bool enable_network_profiles = true;
  bool enable_firewall_rules = true;
  bool include_inactive_firewall_rules = false;
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
  bool enable_muicache = true;
  bool enable_appcompat_flags = true;
  bool enable_typed_paths = true;
  bool enable_last_visited_mru = true;
  bool enable_open_save_mru = true;
  bool enable_ps_history = true;

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
  std::string feature_usage_app_badge_updated_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/"
      "AppBadgeUpdated";
  std::string recent_apps_root_key =
      "Software/Microsoft/Windows/CurrentVersion/Search/RecentApps";
  std::string recent_apps_recent_items_suffix = "RecentItems";
  std::string shimcache_value_path =
      "CurrentControlSet/Control/Session Manager/AppCompatCache/"
      "AppCompatCache";
  std::string bam_root_path = "CurrentControlSet/Services/bam/State/UserSettings";
  std::string dam_root_path = "CurrentControlSet/Services/dam/State/UserSettings";
  std::string bam_legacy_root_path = "CurrentControlSet/Services/bam/UserSettings";
  std::string dam_legacy_root_path = "CurrentControlSet/Services/dam/UserSettings";
  std::string services_root_path = "CurrentControlSet/Services";
  std::string network_profiles_root_key =
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles";
  std::vector<std::string> network_signature_roots = {
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Signatures/Managed",
      "Microsoft/Windows NT/CurrentVersion/NetworkList/Signatures/Unmanaged"};
  std::vector<std::string> firewall_rules_keys = {
      "CurrentControlSet/Services/SharedAccess/Parameters/FirewallPolicy/"
      "FirewallRules",
      "CurrentControlSet/Services/SharedAccess/Parameters/FirewallPolicy/"
      "DomainProfile/FirewallRules",
      "CurrentControlSet/Services/SharedAccess/Parameters/FirewallPolicy/"
      "PublicProfile/FirewallRules",
      "CurrentControlSet/Services/SharedAccess/Parameters/FirewallPolicy/"
      "StandardProfile/FirewallRules"};

  std::string recent_lnk_suffix = "AppData/Roaming/Microsoft/Windows/Recent";
  std::string jump_auto_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations";
  std::string jump_custom_suffix =
      "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations";
  std::string task_scheduler_root_path = "Windows/System32/Tasks";
  std::string task_cache_tasks_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks";
  std::string task_cache_tree_key =
      "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tree";
  std::string ifeo_root_key =
      "Microsoft/Windows NT/CurrentVersion/Image File Execution Options";
  std::string ifeo_wow6432_root_key =
      "Wow6432Node/Microsoft/Windows NT/CurrentVersion/Image File Execution "
      "Options";
  std::string wer_programdata_path = "ProgramData/Microsoft/Windows/WER";
  std::string wer_user_suffix = "AppData/Local/Microsoft/Windows/WER";
  std::string timeline_root_suffix =
      "AppData/Local/ConnectedDevicesPlatform";
  std::string bits_downloader_path = "ProgramData/Microsoft/Network/Downloader";
  std::string hosts_file_path = "Windows/System32/drivers/etc/hosts";
  std::string wmi_repository_path = "Windows/System32/wbem/Repository";
  std::string windows_search_path =
      "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb";
  std::vector<std::string> windows_search_table_allowlist;
  std::string srum_path = "Windows/System32/sru/SRUDB.dat";
  std::string security_log_path = "Windows/System32/winevt/Logs/Security.evtx";
  std::vector<std::string> srum_table_allowlist;

  std::string muicache_key =
      "Software/Classes/Local Settings/MuiCache";
  std::string appcompat_layers_key =
      "Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/Layers";
  std::string appcompat_assist_key =
      "Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/"
      "Compatibility Assistant/Store";
  std::string typed_paths_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths";
  std::string last_visited_mru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/"
      "LastVisitedPidlMRU";
  std::string open_save_mru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/"
      "OpenSavePidlMRU";
  std::string ps_history_suffix =
      "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/"
      "ConsoleHost_history.txt";
};

}  // namespace WindowsDiskAnalysis
