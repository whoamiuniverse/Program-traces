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
  bool enable_bam_dam = true;
  bool enable_jump_lists = true;
  bool enable_lnk_recent = true;
  bool enable_srum = true;
  bool enable_srum_native_parser = true;
  bool srum_fallback_to_binary_on_native_failure = true;
  bool enable_security_log_tamper_check = true;

  std::size_t binary_scan_max_mb = 64;
  std::size_t max_candidates_per_source = 2000;
  std::size_t srum_native_max_records_per_table = 25000;

  std::string userassist_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist";
  std::string runmru_key =
      "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU";
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
  void loadConfiguration();

  std::string resolveSoftwareHivePath(const std::string& disk_root) const;
  std::string resolveSystemHivePath(const std::string& disk_root) const;

  void collectShimCache(const std::string& system_hive_path,
                        std::map<std::string, ProcessInfo>& process_data);
  void collectBamDam(const std::string& system_hive_path,
                     std::map<std::string, ProcessInfo>& process_data);
  void collectUserAssistAndRunMru(
      const std::string& disk_root,
      std::map<std::string, ProcessInfo>& process_data);
  void collectLnkRecent(const std::string& disk_root,
                        std::map<std::string, ProcessInfo>& process_data);
  void collectJumpLists(const std::string& disk_root,
                        std::map<std::string, ProcessInfo>& process_data);
  void collectSrum(const std::string& disk_root,
                   std::map<std::string, ProcessInfo>& process_data);
  std::size_t collectSrumNative(
      const std::filesystem::path& srum_path,
      std::map<std::string, ProcessInfo>& process_data);
  std::size_t collectSrumBinaryFallback(
      const std::filesystem::path& srum_path,
      std::map<std::string, ProcessInfo>& process_data) const;
  void detectSecurityLogTampering(const std::string& disk_root,
                                  std::vector<std::string>& global_tamper_flags);

  std::unique_ptr<RegistryAnalysis::IRegistryParser> parser_;
  std::string os_version_;
  std::string ini_path_;
  ExecutionEvidenceConfig config_;
};

}  // namespace WindowsDiskAnalysis
