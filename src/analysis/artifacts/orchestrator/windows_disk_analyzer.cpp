/// @file windows_disk_analyzer.cpp
/// @brief Основной orchestration-пайплайн анализа артефактов Windows.

#include "windows_disk_analyzer.hpp"

#include <cstdint>
#include <filesystem>
#include <unordered_map>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evt/parser/parser.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

WindowsDiskAnalyzer::WindowsDiskAnalyzer(std::string disk_root,
                                         const std::string& config_path)
    : disk_root_(normalizeDiskRoot(std::move(disk_root))),
      config_path_(config_path) {
  const auto logger = GlobalLogger::get();

  if (disk_root_.empty()) {
    logger->info(
        "Корень анализа: auto (будет выполнен авто-поиск Windows-тома)");
  } else {
    logger->info("Корень анализа: \"{}\"", disk_root_);
  }
  logger->info("Загрузка конфигурации из файла: \"{}\"", config_path);
  detectOSVersion();
  initializeComponents();
}

void WindowsDiskAnalyzer::initializeComponents() {
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.autorun);
    auto registry_parser = std::make_unique<RegistryAnalysis::RegistryParser>();
    autorun_analyzer_ = std::make_unique<AutorunAnalyzer>(
        std::move(registry_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.prefetch);
    auto prefetch_parser = std::make_unique<PrefetchAnalysis::PrefetchParser>();
    prefetch_analyzer_ = std::make_unique<PrefetchAnalyzer>(
        std::move(prefetch_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.eventlog);
    auto evt_parser = std::make_unique<EventLogAnalysis::EvtParser>();
    auto evtx_parser = std::make_unique<EventLogAnalysis::EvtxParser>();
    eventlog_analyzer_ = std::make_unique<EventLogAnalyzer>(
        std::move(evt_parser), std::move(evtx_parser), os_info_.ini_version,
        config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.amcache);
    auto amcache_registry_parser =
        std::make_unique<RegistryAnalysis::RegistryParser>();
    amcache_analyzer_ = std::make_unique<AmcacheAnalyzer>(
        std::move(amcache_registry_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.execution);
    auto execution_registry_parser =
        std::make_unique<RegistryAnalysis::RegistryParser>();
    execution_evidence_analyzer_ = std::make_unique<ExecutionEvidenceAnalyzer>(
        std::move(execution_registry_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    usn_analyzer_ = std::make_unique<USNAnalyzer>(config_path_);
    vss_analyzer_ = std::make_unique<VSSAnalyzer>(config_path_);
  }
}

void WindowsDiskAnalyzer::ensureDirectoryExists(const std::string& path) {
  const fs::path dir_path = fs::path(path).parent_path();
  if (dir_path.empty()) return;

  std::error_code ec;
  if (fs::exists(dir_path, ec) && !ec) return;

  if (ec) {
    throw OutputDirectoryException(path, ec.message());
  }

  fs::create_directories(dir_path, ec);
  if (ec) {
    throw OutputDirectoryException(path, ec.message());
  }
}

void WindowsDiskAnalyzer::resetAnalysisState() {
  autorun_entries_.clear();
  process_data_.clear();
  network_connections_.clear();
  amcache_entries_.clear();
  global_tamper_flags_.clear();
  usn_recovery_evidence_.clear();
  vss_recovery_evidence_.clear();
}

void WindowsDiskAnalyzer::runAutorunStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 1/7: анализ автозагрузки");

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.autorun);
    autorun_entries_ = autorun_analyzer_->collect(disk_root_);
  }

  for (const auto& entry : autorun_entries_) {
    if (entry.path.empty()) continue;
    auto& info = process_data_[entry.path];
    if (info.filename.empty()) {
      info.filename = entry.path;
    }
    appendEvidenceSource(info, "Autorun");
    appendTimelineArtifact(info, "[Autorun] " + entry.location);
  }

  logger->info("Этап 1/7 завершен: записей автозагрузки={}",
               autorun_entries_.size());
}

void WindowsDiskAnalyzer::runAmcacheStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 2/7: анализ Amcache");

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.amcache);
    amcache_entries_ = amcache_analyzer_->collect(disk_root_);
  }

  for (const auto& entry : amcache_entries_) {
    std::string path = entry.file_path.empty() ? entry.name : entry.file_path;
    trim(path);
    if (path.empty()) continue;

    auto& info = process_data_[path];
    if (info.filename.empty()) {
      info.filename = path;
    }

    appendEvidenceSource(info, "Amcache");
    if (!entry.modification_time_str.empty() && entry.modification_time_str != "N/A") {
      info.run_times.push_back(entry.modification_time_str);
      if (EvidenceUtils::isTimestampLike(entry.modification_time_str)) {
        EvidenceUtils::updateTimestampMin(info.first_seen_utc,
                                          entry.modification_time_str);
        EvidenceUtils::updateTimestampMax(info.last_seen_utc,
                                          entry.modification_time_str);
      }
    }

    if (entry.is_deleted) {
      appendTamperFlag(info, "amcache_deleted_trace");
    }
    appendTimelineArtifact(info, "[Amcache] " + path);
  }

  logger->info("Этап 2/7 завершен: записей Amcache={}", amcache_entries_.size());
}

void WindowsDiskAnalyzer::runPrefetchStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 3/7: анализ Prefetch");

  std::vector<ProcessInfo> prefetch_results;
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.prefetch);
    prefetch_results = prefetch_analyzer_->collect(disk_root_);
  }

  for (auto& info : prefetch_results) {
    auto& merged = process_data_[info.filename];
    if (merged.filename.empty()) {
      merged.filename = info.filename;
    }

    merged.run_count += info.run_count;
    merged.run_times.insert(merged.run_times.end(), info.run_times.begin(),
                            info.run_times.end());
    merged.volumes.insert(merged.volumes.end(), info.volumes.begin(),
                          info.volumes.end());
    merged.metrics.insert(merged.metrics.end(), info.metrics.begin(),
                          info.metrics.end());
    appendEvidenceSource(merged, "Prefetch");

    if (!info.run_times.empty()) {
      for (const auto& timestamp : info.run_times) {
        if (EvidenceUtils::isTimestampLike(timestamp)) {
          EvidenceUtils::updateTimestampMin(merged.first_seen_utc, timestamp);
          EvidenceUtils::updateTimestampMax(merged.last_seen_utc, timestamp);
        }
      }
      appendTimelineArtifact(merged, "[Prefetch] last=" + info.run_times.back());
    } else {
      appendTimelineArtifact(merged, "[Prefetch]");
    }
  }

  logger->info("Этап 3/7 завершен: prefetch-процессов={}",
               prefetch_results.size());
}

void WindowsDiskAnalyzer::runEventLogStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 4/7: анализ EventLog");

  std::unordered_map<std::string, uint32_t> run_count_before_eventlog;
  run_count_before_eventlog.reserve(process_data_.size());
  for (const auto& [process_key, info] : process_data_) {
    run_count_before_eventlog[process_key] = info.run_count;
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.eventlog);
    eventlog_analyzer_->collect(disk_root_, process_data_, network_connections_);
  }

  for (auto& [process_key, info] : process_data_) {
    const auto it_before = run_count_before_eventlog.find(process_key);
    const bool is_new_process = it_before == run_count_before_eventlog.end();
    const bool has_new_runs = !is_new_process && info.run_count > it_before->second;

    if (is_new_process || has_new_runs) {
      appendEvidenceSource(info, "EventLog");
      appendTimelineArtifact(
          info, "[EventLog] run_count=" + std::to_string(info.run_count));
    }

    for (const auto& timestamp : info.run_times) {
      if (EvidenceUtils::isTimestampLike(timestamp)) {
        EvidenceUtils::updateTimestampMin(info.first_seen_utc, timestamp);
        EvidenceUtils::updateTimestampMax(info.last_seen_utc, timestamp);
      }
    }
  }

  logger->info("Этап 4/7 завершен: {} сетевых событий", network_connections_.size());
}

void WindowsDiskAnalyzer::runExecutionStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 5/7: доп. источники исполнения");

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.execution);
    execution_evidence_analyzer_->collect(disk_root_, process_data_,
                                          global_tamper_flags_);
  }

  for (const auto& connection : network_connections_) {
    if (connection.process_name.empty()) continue;
    auto& info = process_data_[connection.process_name];
    if (info.filename.empty()) {
      info.filename = connection.process_name;
    }
    appendEvidenceSource(info, "NetworkEvent");
    appendTimelineArtifact(
        info, "[NetworkEvent] " + connection.protocol + ":" +
                  connection.local_address + "->" + connection.remote_address +
                  ":" + std::to_string(connection.port));
  }

  logger->info("Этап 5/7 завершен: {} процессов в агрегате", process_data_.size());
}

void WindowsDiskAnalyzer::runRecoveryStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 6/7: recovery-источники (USN/VSS)");

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    usn_recovery_evidence_ = usn_analyzer_->collect(disk_root_);
    vss_recovery_evidence_ = vss_analyzer_->collect(disk_root_);
  }

  mergeRecoveryEvidenceToProcessData(usn_recovery_evidence_, process_data_);
  mergeRecoveryEvidenceToProcessData(vss_recovery_evidence_, process_data_);

  logger->info("Этап 6/7 завершен: USN={}, VSS={}", usn_recovery_evidence_.size(),
               vss_recovery_evidence_.size());
}

void WindowsDiskAnalyzer::applyGlobalTamperFlags() {
  for (auto& [_, info] : process_data_) {
    for (const auto& global_flag : global_tamper_flags_) {
      appendTamperFlag(info, global_flag);
    }
  }
}

void WindowsDiskAnalyzer::exportCsv(const std::string& output_path) {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 7/7: экспорт CSV");

  const CSVExportOptions csv_export_options = loadCSVExportOptions();
  ensureDirectoryExists(output_path);
  CSVExporter::exportToCSV(output_path, autorun_entries_, process_data_,
                           network_connections_, amcache_entries_,
                           csv_export_options);
  logger->info("Этап 7/7 завершен: экспорт в \"{}\"", output_path);
}

void WindowsDiskAnalyzer::analyze(const std::string& output_path) {
  const auto logger = GlobalLogger::get();
  logger->info("Старт полного анализа артефактов");

  resetAnalysisState();
  runAutorunStage();
  runAmcacheStage();
  runPrefetchStage();
  runEventLogStage();
  runExecutionStage();
  runRecoveryStage();
  applyGlobalTamperFlags();
  exportCsv(output_path);

  logger->info("Анализ завершен: процессов={}, сетевых событий={}",
               process_data_.size(), network_connections_.size());
}

}  // namespace WindowsDiskAnalysis
