/// @file execution_evidence_analyzer.cpp
/// @brief Оркестратор ExecutionEvidenceAnalyzer: загрузка конфига + диспетчеризация коллекторов.

#include "execution_evidence_analyzer.hpp"
#include "execution_evidence_helpers.hpp"

#include <algorithm>
#include <filesystem>
#include <future>
#include <thread>
#include <unordered_map>

#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

// Registry collectors
#include "analysis/artifacts/execution/registry/shimcache_collector.hpp"
#include "analysis/artifacts/execution/registry/bam_dam_collector.hpp"
#include "analysis/artifacts/execution/registry/services_collector.hpp"
#include "analysis/artifacts/execution/registry/network_profiles_collector.hpp"
#include "analysis/artifacts/execution/registry/user_assist_runmru_collector.hpp"
#include "analysis/artifacts/execution/registry/feature_usage_collector.hpp"
#include "analysis/artifacts/execution/registry/recent_apps_collector.hpp"
#include "analysis/artifacts/execution/registry/task_scheduler_collector.hpp"
#include "analysis/artifacts/execution/registry/ifeo_collector.hpp"
#include "analysis/artifacts/execution/registry/muicache_collector.hpp"
#include "analysis/artifacts/execution/registry/appcompat_flags_collector.hpp"
#include "analysis/artifacts/execution/registry/typed_paths_collector.hpp"
#include "analysis/artifacts/execution/registry/last_visited_mru_collector.hpp"
#include "analysis/artifacts/execution/registry/open_save_mru_collector.hpp"

// Filesystem collectors
#include "analysis/artifacts/execution/filesystem/lnk_recent_collector.hpp"
#include "analysis/artifacts/execution/filesystem/jump_lists_collector.hpp"
#include "analysis/artifacts/execution/filesystem/ps_console_history_collector.hpp"
#include "analysis/artifacts/execution/filesystem/wer_reports_collector.hpp"
#include "analysis/artifacts/execution/filesystem/timeline_collector.hpp"
#include "analysis/artifacts/execution/filesystem/bits_queue_collector.hpp"
#include "analysis/artifacts/execution/filesystem/hosts_file_collector.hpp"
#include "analysis/artifacts/execution/filesystem/wmi_repository_collector.hpp"

// Database collectors
#include "analysis/artifacts/execution/database/windows_search_collector.hpp"
#include "analysis/artifacts/execution/database/srum_collector.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;

namespace {

std::string resolveHivePath(const Config& config, const std::string& disk_root,
                            const std::string& os_version,
                            const std::string& section) {
  const std::string relative_path =
      findPathForOsVersion(config, section, os_version);
  if (relative_path.empty()) return {};

  const fs::path full = fs::path(disk_root) / relative_path;
  if (const auto resolved = findPathCaseInsensitive(full); resolved.has_value()) {
    return resolved->string();
  }
  return full.string();
}

void appendRegistryCollectors(
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& software_collectors,
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& system_collectors) {
  software_collectors.push_back(std::make_unique<UserAssistRunMruCollector>());
  software_collectors.push_back(std::make_unique<FeatureUsageCollector>());
  software_collectors.push_back(std::make_unique<RecentAppsCollector>());
  software_collectors.push_back(std::make_unique<NetworkProfilesCollector>());
  software_collectors.push_back(std::make_unique<TaskSchedulerCollector>());
  software_collectors.push_back(std::make_unique<IfeoCollector>());
  software_collectors.push_back(std::make_unique<MuiCacheCollector>());
  software_collectors.push_back(std::make_unique<AppCompatFlagsCollector>());
  software_collectors.push_back(std::make_unique<TypedPathsCollector>());
  software_collectors.push_back(std::make_unique<LastVisitedMruCollector>());
  software_collectors.push_back(std::make_unique<OpenSaveMruCollector>());

  system_collectors.push_back(std::make_unique<ShimCacheCollector>());
  system_collectors.push_back(std::make_unique<BamDamCollector>());
  system_collectors.push_back(std::make_unique<ServicesCollector>());
}

void appendFilesystemCollectors(
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& collectors) {
  collectors.push_back(std::make_unique<LnkRecentCollector>());
  collectors.push_back(std::make_unique<JumpListsCollector>());
  collectors.push_back(std::make_unique<PsConsoleHistoryCollector>());
  collectors.push_back(std::make_unique<WerReportsCollector>());
  collectors.push_back(std::make_unique<TimelineCollector>());
  collectors.push_back(std::make_unique<BitsQueueCollector>());
  collectors.push_back(std::make_unique<HostsFileCollector>());
  collectors.push_back(std::make_unique<WmiRepositoryCollector>());
}

void appendDatabaseCollectors(
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& collectors) {
  collectors.push_back(std::make_unique<WindowsSearchCollector>());
  collectors.push_back(std::make_unique<SrumCollector>());
}

}  // namespace

ExecutionEvidenceAnalyzer::ExecutionEvidenceAnalyzer(
    std::string os_version, std::string ini_path)
    : os_version_(std::move(os_version)),
      ini_path_(std::move(ini_path)) {
  trim(os_version_);
  loadConfiguration();
  initializeCollectors();
}

void ExecutionEvidenceAnalyzer::initializeCollectors() {
  software_collectors_.clear();
  system_collectors_.clear();
  filesystem_collectors_.clear();
  database_collectors_.clear();
  software_collectors_.reserve(11);
  system_collectors_.reserve(4);
  filesystem_collectors_.reserve(8);
  database_collectors_.reserve(2);

  appendRegistryCollectors(software_collectors_, system_collectors_);
  appendFilesystemCollectors(filesystem_collectors_);
  appendDatabaseCollectors(database_collectors_);
}

void ExecutionEvidenceAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(ini_path_, false, false);

    if (!config.hasSection("ExecutionArtifacts")) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Секция [ExecutionArtifacts] не найдена, используются "
                    "значения по умолчанию");
      return;
    }

    auto readBool = [&](const std::string& key, const bool default_value) {
      try {
        return config.getBool("ExecutionArtifacts", key, default_value);
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [ExecutionArtifacts]/{}", key);
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [ExecutionArtifacts]/{}: {}", key, e.what());
        return default_value;
      }
    };

    auto readSize = [&](const std::string& key, const std::size_t default_value) {
      try {
        const int value = config.getInt("ExecutionArtifacts", key,
                                        static_cast<int>(default_value));
        if (value < 0) {
          return default_value;
        }
        return static_cast<std::size_t>(value);
      } catch (...) {
        return default_value;
      }
    };

    auto readString = [&](const std::string& key, std::string default_value) {
      try {
        const std::string raw =
            config.getString("ExecutionArtifacts", key, default_value);
        return raw.empty() ? default_value : raw;
      } catch (...) {
        return default_value;
      }
    };

    auto readList = [&](const std::string& key,
                        std::vector<std::string> default_value) {
      try {
        if (!config.hasKey("ExecutionArtifacts", key)) return default_value;
        const std::string raw = config.getString("ExecutionArtifacts", key, "");
        auto parsed = parseListSetting(raw);
        return parsed.empty() ? default_value : parsed;
      } catch (...) {
        return default_value;
      }
    };

    config_.enable_shimcache =
        readBool("EnableShimCache", config_.enable_shimcache);
    config_.enable_userassist =
        readBool("EnableUserAssist", config_.enable_userassist);
    config_.enable_runmru = readBool("EnableRunMRU", config_.enable_runmru);
    config_.enable_feature_usage =
        readBool("EnableFeatureUsage", config_.enable_feature_usage);
    config_.enable_recent_apps =
        readBool("EnableRecentApps", config_.enable_recent_apps);
    config_.enable_bam_dam = readBool("EnableBamDam", config_.enable_bam_dam);
    config_.enable_services =
        readBool("EnableServices", config_.enable_services);
    config_.enable_hosts_file =
        readBool("EnableHostsFile", config_.enable_hosts_file);
    config_.enable_network_profiles =
        readBool("EnableNetworkProfiles", config_.enable_network_profiles);
    config_.enable_jump_lists =
        readBool("EnableJumpLists", config_.enable_jump_lists);
    config_.enable_lnk_recent =
        readBool("EnableLnkRecent", config_.enable_lnk_recent);
    config_.enable_task_scheduler =
        readBool("EnableTaskScheduler", config_.enable_task_scheduler);
    config_.enable_wer = readBool("EnableWER", config_.enable_wer);
    config_.enable_ifeo = readBool("EnableIFEO", config_.enable_ifeo);
    config_.enable_timeline = readBool("EnableTimeline", config_.enable_timeline);
    config_.enable_bits = readBool("EnableBITS", config_.enable_bits);
    config_.enable_wmi_repository =
        readBool("EnableWMIRepository", config_.enable_wmi_repository);
    config_.enable_windows_search =
        readBool("EnableWindowsSearch", config_.enable_windows_search);
    config_.enable_windows_search_native_parser = readBool(
        "EnableNativeWindowsSearchParser",
        config_.enable_windows_search_native_parser);
    config_.windows_search_fallback_to_binary_on_native_failure = readBool(
        "WindowsSearchFallbackToBinaryOnNativeFailure",
        config_.windows_search_fallback_to_binary_on_native_failure);
    config_.enable_srum = readBool("EnableSRUM", config_.enable_srum);
    config_.enable_srum_native_parser =
        readBool("EnableNativeSRUM", config_.enable_srum_native_parser);
    config_.srum_fallback_to_binary_on_native_failure = readBool(
        "SrumFallbackToBinaryOnNativeFailure",
        config_.srum_fallback_to_binary_on_native_failure);
    config_.enable_security_log_tamper_check = readBool(
        "EnableSecurityLogTamperCheck", config_.enable_security_log_tamper_check);
    config_.enable_system_log_tamper_check = readBool(
        "EnableSystemLogTamperCheck", config_.enable_system_log_tamper_check);
    config_.enable_registry_state_tamper_check = readBool(
        "EnableRegistryStateTamperCheck", config_.enable_registry_state_tamper_check);
    config_.enable_artifact_presence_tamper_check = readBool(
        "EnableArtifactPresenceTamperCheck", config_.enable_artifact_presence_tamper_check);
    config_.enable_muicache = readBool("EnableMuiCache", config_.enable_muicache);
    config_.enable_appcompat_flags =
        readBool("EnableAppCompatFlags", config_.enable_appcompat_flags);
    config_.enable_typed_paths =
        readBool("EnableTypedPaths", config_.enable_typed_paths);
    config_.enable_last_visited_mru =
        readBool("EnableLastVisitedMRU", config_.enable_last_visited_mru);
    config_.enable_open_save_mru =
        readBool("EnableOpenSaveMRU", config_.enable_open_save_mru);
    config_.enable_ps_history =
        readBool("EnablePSHistory", config_.enable_ps_history);

    config_.muicache_key = readString("MuiCacheKey", config_.muicache_key);
    config_.appcompat_layers_key =
        readString("AppCompatLayersKey", config_.appcompat_layers_key);
    config_.appcompat_assist_key =
        readString("AppCompatAssistKey", config_.appcompat_assist_key);
    config_.typed_paths_key =
        readString("TypedPathsKey", config_.typed_paths_key);
    config_.last_visited_mru_key =
        readString("LastVisitedMruKey", config_.last_visited_mru_key);
    config_.open_save_mru_key =
        readString("OpenSaveMruKey", config_.open_save_mru_key);
    config_.ps_history_suffix =
        readString("PSHistorySuffix", config_.ps_history_suffix);

    config_.binary_scan_max_mb =
        readSize("BinaryScanMaxMB", config_.binary_scan_max_mb);
    config_.max_candidates_per_source =
        readSize("MaxCandidatesPerSource", config_.max_candidates_per_source);
    config_.srum_native_max_records_per_table = readSize(
        "SrumNativeMaxRecordsPerTable", config_.srum_native_max_records_per_table);
    config_.windows_search_native_max_records_per_table =
        readSize("WindowsSearchNativeMaxRecordsPerTable",
                 config_.windows_search_native_max_records_per_table);

    config_.userassist_key = readString("UserAssistKey", config_.userassist_key);
    config_.runmru_key = readString("RunMRUKey", config_.runmru_key);
    config_.feature_usage_app_switched_key =
        readString("FeatureUsageAppSwitchedKey",
                   config_.feature_usage_app_switched_key);
    config_.feature_usage_show_jumpview_key =
        readString("FeatureUsageShowJumpViewKey",
                   config_.feature_usage_show_jumpview_key);
    config_.feature_usage_app_badge_updated_key =
        readString("FeatureUsageAppBadgeUpdatedKey",
                   config_.feature_usage_app_badge_updated_key);
    config_.recent_apps_root_key =
        readString("RecentAppsRootKey", config_.recent_apps_root_key);
    config_.recent_apps_recent_items_suffix = readString(
        "RecentAppsRecentItemsSuffix", config_.recent_apps_recent_items_suffix);
    config_.shimcache_value_path =
        readString("ShimCacheValuePath", config_.shimcache_value_path);
    config_.bam_root_path = readString("BamRootPath", config_.bam_root_path);
    config_.dam_root_path = readString("DamRootPath", config_.dam_root_path);
    config_.bam_legacy_root_path =
        readString("BamLegacyRootPath", config_.bam_legacy_root_path);
    config_.dam_legacy_root_path =
        readString("DamLegacyRootPath", config_.dam_legacy_root_path);
    config_.services_root_path =
        readString("ServicesRootPath", config_.services_root_path);
    config_.network_profiles_root_key =
        readString("NetworkProfilesRootKey", config_.network_profiles_root_key);
    config_.recent_lnk_suffix =
        readString("RecentLnkPath", config_.recent_lnk_suffix);
    config_.jump_auto_suffix = readString("JumpListAutoPath", config_.jump_auto_suffix);
    config_.jump_custom_suffix =
        readString("JumpListCustomPath", config_.jump_custom_suffix);
    config_.task_scheduler_root_path =
        readString("TaskSchedulerPath", config_.task_scheduler_root_path);
    config_.task_cache_tasks_key =
        readString("TaskCacheTasksKey", config_.task_cache_tasks_key);
    config_.task_cache_tree_key =
        readString("TaskCacheTreeKey", config_.task_cache_tree_key);
    config_.ifeo_root_key = readString("IFEORootKey", config_.ifeo_root_key);
    config_.ifeo_wow6432_root_key =
        readString("IFEOWow6432RootKey", config_.ifeo_wow6432_root_key);
    config_.wer_programdata_path =
        readString("WERProgramDataPath", config_.wer_programdata_path);
    config_.wer_user_suffix = readString("WERUserPath", config_.wer_user_suffix);
    config_.timeline_root_suffix =
        readString("TimelineRootPath", config_.timeline_root_suffix);
    config_.bits_downloader_path =
        readString("BITSDownloaderPath", config_.bits_downloader_path);
    config_.hosts_file_path =
        readString("HostsFilePath", config_.hosts_file_path);
    config_.wmi_repository_path =
        readString("WMIRepositoryPath", config_.wmi_repository_path);
    config_.windows_search_path =
        readString("WindowsSearchPath", config_.windows_search_path);
    config_.srum_path = readString("SRUMPath", config_.srum_path);
    config_.security_log_path =
        readString("SecurityLogPath", config_.security_log_path);
    config_.system_log_path =
        readString("SystemLogPath", config_.system_log_path);
    config_.network_signature_roots =
        readList("NetworkSignatureRoots", config_.network_signature_roots);
    config_.srum_table_allowlist =
        readList("SrumTableAllowlist", config_.srum_table_allowlist);
    config_.windows_search_table_allowlist = readList(
        "WindowsSearchTableAllowlist", config_.windows_search_table_allowlist);

    if (config.hasSection("Performance")) {
      try {
        enable_parallel_groups_ = config.getBool(
            "Performance", "EnableParallelStages", enable_parallel_groups_);
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [Performance]/EnableParallelStages");
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Performance]/EnableParallelStages: {}",
                      e.what());
      }

      try {
        enable_parallel_user_hive_analysis_ = config.getBool(
            "Performance", "EnableParallelUserHives",
            config.getBool("Performance", "EnableParallelStages",
                           enable_parallel_user_hive_analysis_));
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [Performance]/EnableParallelUserHives");
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
            "Ошибка чтения [Performance]/EnableParallelUserHives: {}",
            e.what());
      }

      try {
        const int configured_threads = config.getInt(
            "Performance", "WorkerThreads", static_cast<int>(worker_threads_));
        if (configured_threads > 0) {
          worker_threads_ = static_cast<std::size_t>(configured_threads);
        }
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [Performance]/WorkerThreads");
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Performance]/WorkerThreads: {}", e.what());
      }
      worker_threads_ = std::max<std::size_t>(1, worker_threads_);
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить [ExecutionArtifacts]");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения конфигурации ExecutionArtifacts: {}", e.what());
  }
}

/// @brief Оркестрирует все этапы расширенного сбора execution evidence.
/// @param disk_root Корень Windows-раздела.
/// @param process_data Карта процессов для обогащения.
/// @param global_tamper_flags Legacy-параметр (не используется в production pipeline).
void ExecutionEvidenceAnalyzer::collect(
    const std::string& disk_root,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<std::string>& global_tamper_flags) {
  const auto logger = GlobalLogger::get();
  logger->info("Запуск расширенного анализа источников исполнения");

  const Config hive_config(ini_path_, false, false);
  const std::string software_hive_path =
      resolveHivePath(hive_config, disk_root, os_version_, "OSInfoRegistryPaths");
  const std::string system_hive_path = resolveHivePath(
      hive_config, disk_root, os_version_, "OSInfoSystemRegistryPaths");

  ExecutionEvidenceContext ctx{disk_root, software_hive_path, system_hive_path,
                               enable_parallel_user_hive_analysis_, worker_threads_,
                               config_};

  using LocalMap = std::unordered_map<std::string, ProcessInfo>;
  auto run_group = [&ctx](CollectorGroup& group) {
    LocalMap local;
    for (auto& collector : group) {
      collector->collect(ctx, local);
    }
    return local;
  };

  if (enable_parallel_groups_ && worker_threads_ > 1) {
    std::vector<std::future<LocalMap>> tasks;
    tasks.reserve(4);
    tasks.push_back(
        std::async(std::launch::async, run_group, std::ref(software_collectors_)));
    tasks.push_back(
        std::async(std::launch::async, run_group, std::ref(system_collectors_)));
    tasks.push_back(
        std::async(std::launch::async, run_group, std::ref(filesystem_collectors_)));
    tasks.push_back(
        std::async(std::launch::async, run_group, std::ref(database_collectors_)));

    for (auto& task : tasks) {
      mergeProcessDataMaps(process_data, task.get());
    }
  } else {
    mergeProcessDataMaps(process_data, run_group(software_collectors_));
    mergeProcessDataMaps(process_data, run_group(system_collectors_));
    mergeProcessDataMaps(process_data, run_group(filesystem_collectors_));
    mergeProcessDataMaps(process_data, run_group(database_collectors_));
  }

  (void)global_tamper_flags;
}

}  // namespace WindowsDiskAnalysis
