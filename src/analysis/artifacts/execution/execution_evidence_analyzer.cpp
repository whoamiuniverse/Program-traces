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
#include "analysis/artifacts/execution/registry/user_assist_runmru_collector.hpp"
#include "analysis/artifacts/execution/registry/task_scheduler_collector.hpp"

// Filesystem collectors
#include "analysis/artifacts/execution/filesystem/lnk_recent_collector.hpp"
#include "analysis/artifacts/execution/filesystem/jump_lists_collector.hpp"
#include "analysis/artifacts/execution/filesystem/ps_console_history_collector.hpp"

// Database collectors
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
  // Целевые источники: UserAssist/RunMRU, Task Scheduler, ShimCache, BAM/DAM.
  software_collectors.push_back(std::make_unique<UserAssistRunMruCollector>());
  software_collectors.push_back(std::make_unique<TaskSchedulerCollector>());

  system_collectors.push_back(std::make_unique<ShimCacheCollector>());
  system_collectors.push_back(std::make_unique<BamDamCollector>());
}

void appendFilesystemCollectors(
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& collectors) {
  // Целевые источники: LNK, Jump Lists, PowerShell History.
  collectors.push_back(std::make_unique<LnkRecentCollector>());
  collectors.push_back(std::make_unique<JumpListsCollector>());
  collectors.push_back(std::make_unique<PsConsoleHistoryCollector>());
}

void appendDatabaseCollectors(
    std::vector<std::unique_ptr<IExecutionArtifactCollector>>& collectors) {
  // Целевой источник: SRUM.
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
  software_collectors_.reserve(2);
  system_collectors_.reserve(2);
  filesystem_collectors_.reserve(3);
  database_collectors_.reserve(1);

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

    // Источники запуска всегда анализируются полным набором из 11 артефактов.
    // Переключатели Enable* и parser/fallback-тумблеры больше не применяются.

    config_.ps_history_suffix =
        readString("PSHistorySuffix", config_.ps_history_suffix);

    config_.binary_scan_max_mb =
        readSize("BinaryScanMaxMB", config_.binary_scan_max_mb);
    config_.max_candidates_per_source =
        readSize("MaxCandidatesPerSource", config_.max_candidates_per_source);
    config_.srum_native_max_records_per_table = readSize(
        "SrumNativeMaxRecordsPerTable", config_.srum_native_max_records_per_table);

    config_.userassist_key = readString("UserAssistKey", config_.userassist_key);
    config_.runmru_key = readString("RunMRUKey", config_.runmru_key);
    config_.shimcache_value_path =
        readString("ShimCacheValuePath", config_.shimcache_value_path);
    config_.bam_root_path = readString("BamRootPath", config_.bam_root_path);
    config_.dam_root_path = readString("DamRootPath", config_.dam_root_path);
    config_.bam_legacy_root_path =
        readString("BamLegacyRootPath", config_.bam_legacy_root_path);
    config_.dam_legacy_root_path =
        readString("DamLegacyRootPath", config_.dam_legacy_root_path);
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
    config_.srum_path = readString("SRUMPath", config_.srum_path);
    config_.srum_table_allowlist =
        readList("SrumTableAllowlist", config_.srum_table_allowlist);

    // Параметры выбора источников намеренно игнорируются:
    // анализ выполняется всегда по фиксированному набору.
    auto warnIgnoredSourceOption = [&](const std::string& key) {
      if (config.hasKey("ExecutionArtifacts", key)) {
        logger->warn(
            "Параметр [ExecutionArtifacts]/{} игнорируется: выбор источников отключен",
            key);
      }
    };
    for (const std::string& key : {
             "EnableShimCache",
             "EnableUserAssist",
             "EnableRunMRU",
             "EnableBamDam",
             "EnableJumpLists",
             "EnableLnkRecent",
             "EnableTaskScheduler",
             "EnableSRUM",
             "EnableNativeSRUM",
             "SrumFallbackToBinaryOnNativeFailure",
             "EnablePSHistory",
             "EnableFeatureUsage",
             "EnableRecentApps",
             "EnableServices",
             "EnableHostsFile",
             "EnableNetworkProfiles",
             "EnableWER",
             "EnableIFEO",
             "EnableTimeline",
             "EnableBITS",
             "EnableWMIRepository",
             "EnableWindowsSearch",
             "EnableNativeWindowsSearchParser",
             "WindowsSearchFallbackToBinaryOnNativeFailure",
             "EnableMuiCache",
             "EnableAppCompatFlags",
             "EnableTypedPaths",
             "EnableLastVisitedMRU",
             "EnableOpenSaveMRU"}) {
      warnIgnoredSourceOption(key);
    }

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
/// @details В расширенном этапе используются только источники из целевого
/// набора артефактов запуска ПО.
void ExecutionEvidenceAnalyzer::collect(
    const std::string& disk_root,
    std::unordered_map<std::string, ProcessInfo>& process_data) {
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
}

}  // namespace WindowsDiskAnalysis
