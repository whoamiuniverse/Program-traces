/// @file windows_disk_analyzer.cpp
/// @brief Основной orchestration-пайплайн анализа артефактов Windows.

#include "windows_disk_analyzer.hpp"

#include <cstdint>
#include <filesystem>
#include <future>
#include <unordered_map>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/event_logs/eventlog_analyzer.hpp"
#include "analysis/artifacts/event_logs/security_context_analyzer.hpp"
#include "analysis/artifacts/recovery/fs_metadata/ntfs_metadata_analyzer.hpp"
#include "analysis/artifacts/recovery/hiber/hibernation_analyzer.hpp"
#include "analysis/artifacts/recovery/registry/registry_log_analyzer.hpp"
#include "analysis/artifacts/recovery/usn/usn_analyzer.hpp"
#include "analysis/artifacts/recovery/vss/vss_analyzer.hpp"
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
    // Все collectors регистрируются через IEventLogCollector (OCP).
    // Для добавления нового — одна строка push_back без изменения заголовка.
    eventlog_collectors_.push_back(std::make_unique<EventLogAnalyzer>(
        std::make_unique<EventLogAnalysis::EvtParser>(),
        std::make_unique<EventLogAnalysis::EvtxParser>(),
        os_info_.ini_version, config_path_));

    eventlog_collectors_.push_back(std::make_unique<SecurityContextAnalyzer>(
        std::make_unique<EventLogAnalysis::EvtParser>(),
        std::make_unique<EventLogAnalysis::EvtxParser>(),
        os_info_.ini_version, config_path_));
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
    execution_evidence_analyzer_ = std::make_unique<ExecutionEvidenceAnalyzer>(
        os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    // Все recovery-анализаторы регистрируются через NamedRecoveryAnalyzer (OCP).
    // Добавление нового — одна строка push_back без изменения заголовка,
    // resetAnalysisState() или runRecoveryStage().
    recovery_analyzers_.push_back({"USN",      std::make_unique<USNAnalyzer>(config_path_)});
    recovery_analyzers_.push_back({"VSS",      std::make_unique<VSSAnalyzer>(config_path_)});
    recovery_analyzers_.push_back({"Hiber",    std::make_unique<HibernationAnalyzer>(config_path_)});
    recovery_analyzers_.push_back({"NTFS",     std::make_unique<NTFSMetadataAnalyzer>(config_path_)});
    recovery_analyzers_.push_back({"Registry", std::make_unique<RegistryLogAnalyzer>(config_path_)});
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
  recovery_evidence_.clear();
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
    for (const auto& collector : eventlog_collectors_) {
      collector->collect(disk_root_, process_data_, network_connections_);
    }
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
    std::string process_key = connection.process_name;
    if (process_key.empty()) {
      process_key = connection.application;
    }
    if (process_key.empty()) continue;

    auto& info = process_data_[process_key];
    if (info.filename.empty()) {
      info.filename = process_key;
    }
    appendEvidenceSource(info, "NetworkEvent");
    const auto format_port = [](const uint16_t port) {
      return port == 0 ? std::string("-") : std::to_string(port);
    };
    const std::string protocol =
        connection.protocol.empty() ? "N/A" : connection.protocol;
    const std::string source_ip =
        connection.source_ip.empty() ? "N/A" : connection.source_ip;
    const std::string dest_ip =
        connection.dest_ip.empty() ? "N/A" : connection.dest_ip;
    const std::string direction =
        connection.direction.empty() ? "N/A" : connection.direction;
    const std::string action =
        connection.action.empty() ? "N/A" : connection.action;

    appendTimelineArtifact(
        info,
        "[NetworkEvent] id=" + std::to_string(connection.event_id) + " " +
            protocol + " " + source_ip + ":" + format_port(connection.source_port) +
            "->" + dest_ip + ":" + format_port(connection.dest_port) + " " +
            "pid=" + std::to_string(connection.process_id) + " dir=" + direction +
            " action=" + action);
  }

  logger->info("Этап 5/7 завершен: {} процессов в агрегате", process_data_.size());
}

void WindowsDiskAnalyzer::runRecoveryStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 6/7: recovery-источники (USN/VSS/Hiber/NTFS/Registry)");

  const bool run_parallel = performance_options_.enable_parallel_stages &&
                            performance_options_.max_io_workers > 1;

  // Резервируем память заранее: 5 анализаторов × max_candidates каждый.
  // Избегаем многократных реаллокаций при последовательном push_back/insert.
  constexpr std::size_t kDefaultCandidatesPerSource = 2000;
  recovery_evidence_.reserve(recovery_analyzers_.size() * kDefaultCandidatesPerSource);

  // Результаты по каждому анализатору: {label, evidence}.
  // Индекс совпадает с recovery_analyzers_, что позволяет безопасно
  // обращаться к метке при обработке исключений из future.
  std::vector<std::pair<std::string, std::vector<RecoveryEvidence>>>
      per_analyzer(recovery_analyzers_.size());
  for (std::size_t i = 0; i < recovery_analyzers_.size(); ++i) {
    per_analyzer[i].first = recovery_analyzers_[i].label;
  }

  if (run_parallel) {
    logger->info("Recovery: параллельный режим включен (MaxIOWorkers={})",
                 performance_options_.max_io_workers);

    struct Task {
      std::size_t                              index;
      std::future<std::vector<RecoveryEvidence>> future;
    };

    std::vector<Task> tasks;
    tasks.reserve(recovery_analyzers_.size());

    for (std::size_t i = 0; i < recovery_analyzers_.size(); ++i) {
      // Захватываем raw-указатель — вектор не изменяется во время async.
      IRecoveryAnalyzer* ptr = recovery_analyzers_[i].analyzer.get();
      tasks.push_back(
          {i, std::async(std::launch::async,
                         [ptr, this] { return ptr->collect(disk_root_); })});
    }

    for (auto& task : tasks) {
      try {
        per_analyzer[task.index].second = task.future.get();
      } catch (const std::exception& e) {
        logger->error("Recovery({}): ошибка этапа",
                      recovery_analyzers_[task.index].label);
        logger->debug("Recovery({}) exception: {}",
                      recovery_analyzers_[task.index].label, e.what());
      } catch (...) {
        logger->error("Recovery({}): неизвестная ошибка этапа",
                      recovery_analyzers_[task.index].label);
      }
    }
  } else {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    for (std::size_t i = 0; i < recovery_analyzers_.size(); ++i) {
      per_analyzer[i].second =
          recovery_analyzers_[i].analyzer->collect(disk_root_);
    }
  }

  // Мерж в общую таблицу процессов и формирование строки итогового лога.
  std::string summary;
  for (auto& [label, evidence] : per_analyzer) {
    if (!summary.empty()) summary += ", ";
    summary += label + "=" + std::to_string(evidence.size());

    mergeRecoveryEvidenceToProcessData(evidence, process_data_);
    recovery_evidence_.insert(recovery_evidence_.end(),
                              std::make_move_iterator(evidence.begin()),
                              std::make_move_iterator(evidence.end()));
  }

  logger->info("Этап 6/7 завершен: {}", summary);
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
