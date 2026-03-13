/// @file windows_disk_analyzer.cpp
/// @brief Основной orchestration-пайплайн анализа артефактов Windows.

#include "windows_disk_analyzer.hpp"

#include <cstdint>
#include <filesystem>
#include <future>
#include <iterator>
#include <set>
#include <string_view>
#include <unordered_map>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/event_logs/eventlog_analyzer.hpp"
#include "analysis/artifacts/event_logs/security_context_analyzer.hpp"
#include "analysis/artifacts/recovery/fs_metadata/ntfs_metadata_analyzer.hpp"
#include "analysis/artifacts/recovery/hiber/hibernation_analyzer.hpp"
#include "analysis/artifacts/recovery/registry/registry_log_analyzer.hpp"
#include "analysis/artifacts/recovery/usn/usn_analyzer.hpp"
#include "analysis/artifacts/recovery/vss/vss_analyzer.hpp"
#include "common/config_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evt/parser/parser.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

namespace {

void updateProcessTimestampBounds(ProcessInfo& info,
                                  const std::string& timestamp) {
  if (!EvidenceUtils::isTimestampLike(timestamp)) {
    return;
  }

  if (info.first_seen_utc.empty() || timestamp < info.first_seen_utc) {
    info.first_seen_utc = timestamp;
  }
  if (info.last_seen_utc.empty() || timestamp > info.last_seen_utc) {
    info.last_seen_utc = timestamp;
  }
}

void updateProcessTimestampBoundsFromRunTimes(ProcessInfo& info) {
  for (const auto& timestamp : info.run_times) {
    updateProcessTimestampBounds(info, timestamp);
  }
}

std::string formatPort(const uint16_t port) {
  return port == 0 ? std::string("-") : std::to_string(port);
}

std::string_view valueOrNA(const std::string& value) {
  return value.empty() ? std::string_view("N/A") : std::string_view(value);
}

std::string buildNetworkTimelineArtifact(const NetworkConnection& connection) {
  std::string artifact;
  artifact.reserve(96 + connection.protocol.size() + connection.source_ip.size() +
                   connection.dest_ip.size() + connection.direction.size() +
                   connection.action.size());

  artifact += "[NetworkEvent] id=";
  artifact += std::to_string(connection.event_id);
  artifact.push_back(' ');
  artifact += valueOrNA(connection.protocol);
  artifact.push_back(' ');
  artifact += valueOrNA(connection.source_ip);
  artifact.push_back(':');
  artifact += formatPort(connection.source_port);
  artifact += "->";
  artifact += valueOrNA(connection.dest_ip);
  artifact.push_back(':');
  artifact += formatPort(connection.dest_port);
  artifact += " pid=";
  artifact += std::to_string(connection.process_id);
  artifact += " dir=";
  artifact += valueOrNA(connection.direction);
  artifact += " action=";
  artifact += valueOrNA(connection.action);
  return artifact;
}

bool endsWithCaseInsensitive(const std::string& value,
                             const std::string& suffix) {
  if (value.size() < suffix.size()) {
    return false;
  }
  const std::string lowered_value = to_lower(value);
  const std::string lowered_suffix = to_lower(suffix);
  return lowered_value.rfind(lowered_suffix) ==
         lowered_value.size() - lowered_suffix.size();
}

bool looksLikeProcessImage(const std::string& process_key) {
  if (process_key.empty()) {
    return false;
  }

  const std::string filename = getLastPathComponent(process_key, '/');
  const std::string candidate =
      filename.empty() ? getLastPathComponent(process_key, '\\') : filename;
  const std::string normalized = candidate.empty() ? process_key : candidate;
  return endsWithCaseInsensitive(normalized, ".exe") ||
         endsWithCaseInsensitive(normalized, ".com") ||
         endsWithCaseInsensitive(normalized, ".bat") ||
         endsWithCaseInsensitive(normalized, ".cmd") ||
         endsWithCaseInsensitive(normalized, ".ps1") ||
         endsWithCaseInsensitive(normalized, ".msi");
}

std::string buildPrefetchLookupKey(const std::string& process_key) {
  std::string filename = getLastPathComponent(process_key, '/');
  if (filename.empty()) {
    filename = getLastPathComponent(process_key, '\\');
  }
  if (filename.empty()) {
    filename = process_key;
  }
  return to_lower(filename);
}

bool hasAnySource(const ProcessInfo& info,
                  const std::vector<std::string>& runtime_sources) {
  for (const auto& source : info.evidence_sources) {
    for (const auto& expected : runtime_sources) {
      if (to_lower(source) == to_lower(expected)) {
        return true;
      }
    }
  }
  return false;
}

std::set<std::string> buildPrefetchFilenameSet(const std::string& disk_root,
                                               const std::string& config_path,
                                               const std::string& os_version) {
  std::set<std::string> results;
  Config config(config_path, false, false);
  std::string prefetch_relative = WindowsDiskAnalysis::ConfigUtils::
      getWithVersionFallback(config, os_version, "PrefetchPath");
  trim(prefetch_relative);
  std::ranges::replace(prefetch_relative, '\\', '/');
  if (prefetch_relative.empty()) {
    return results;
  }

  const fs::path prefetch_candidate = fs::path(disk_root) / prefetch_relative;
  const auto resolved = PathUtils::findPathCaseInsensitive(prefetch_candidate);
  if (!resolved.has_value()) {
    return results;
  }

  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(*resolved, ec)) {
    if (ec || !entry.is_regular_file()) {
      continue;
    }

    const std::string extension = to_lower(entry.path().extension().string());
    if (extension != ".pf") {
      continue;
    }

    std::string stem = to_lower(entry.path().stem().string());
    trim(stem);
    if (stem.empty()) {
      continue;
    }
    results.insert(stem);

    const std::size_t hash_sep = stem.rfind('-');
    if (hash_sep != std::string::npos && hash_sep > 0) {
      results.insert(stem.substr(0, hash_sep));
    }
  }

  return results;
}

template <typename T>
void appendMovedVector(std::vector<T>& destination, std::vector<T>& source) {
  if (source.empty()) {
    return;
  }

  destination.reserve(destination.size() + source.size());
  destination.insert(destination.end(),
                     std::make_move_iterator(source.begin()),
                     std::make_move_iterator(source.end()));
}

ProcessInfo& ensureProcessEntry(std::unordered_map<std::string, ProcessInfo>& process_data,
                                const std::string& process_key) {
  auto& info = process_data[process_key];
  if (info.filename.empty()) {
    info.filename = process_key;
  }
  return info;
}

ProcessInfo& ensureProcessEntry(std::unordered_map<std::string, ProcessInfo>& process_data,
                                std::string& process_key) {
  auto& info = process_data[process_key];
  if (info.filename.empty()) {
    info.filename = std::move(process_key);
  }
  return info;
}

void appendPrefetchTimeline(ProcessInfo& merged, const ProcessInfo& prefetch_info) {
  if (prefetch_info.run_times.empty()) {
    appendTimelineArtifact(merged, "[Prefetch]");
    return;
  }

  std::string artifact;
  artifact.reserve(16 + prefetch_info.run_times.back().size());
  artifact = "[Prefetch] last=";
  artifact += prefetch_info.run_times.back();
  appendTimelineArtifact(merged, artifact);
}

void mergePrefetchProcessInfo(ProcessInfo& merged, ProcessInfo& prefetch_info) {
  merged.run_count += prefetch_info.run_count;
  appendEvidenceSource(merged, "Prefetch");

  for (const auto& timestamp : prefetch_info.run_times) {
    updateProcessTimestampBounds(merged, timestamp);
  }
  appendPrefetchTimeline(merged, prefetch_info);

  appendMovedVector(merged.run_times, prefetch_info.run_times);
  appendMovedVector(merged.volumes, prefetch_info.volumes);
  appendMovedVector(merged.metrics, prefetch_info.metrics);
}

std::string buildEventLogTimelineArtifact(const uint32_t run_count) {
  std::string artifact;
  artifact.reserve(32);
  artifact = "[EventLog] run_count=";
  artifact += std::to_string(run_count);
  return artifact;
}

std::unordered_map<std::string, uint32_t> buildRunCountSnapshot(
    const std::unordered_map<std::string, ProcessInfo>& process_data) {
  std::unordered_map<std::string, uint32_t> snapshot;
  snapshot.reserve(process_data.size());
  for (const auto& [process_key, info] : process_data) {
    snapshot.emplace(process_key, info.run_count);
  }
  return snapshot;
}

bool shouldAppendEventLogEvidence(
    const std::unordered_map<std::string, uint32_t>& run_count_snapshot,
    const std::string& process_key, const uint32_t run_count) {
  const auto it_before = run_count_snapshot.find(process_key);
  const bool is_new_process = it_before == run_count_snapshot.end();
  const bool has_new_runs = !is_new_process && run_count > it_before->second;
  return is_new_process || has_new_runs;
}

void appendEventLogEvidence(ProcessInfo& info) {
  appendEvidenceSource(info, "EventLog");
  appendTimelineArtifact(info, buildEventLogTimelineArtifact(info.run_count));
}

const std::string* resolveProcessKey(const NetworkConnection& connection) {
  if (!connection.process_name.empty()) {
    return &connection.process_name;
  }
  if (!connection.application.empty()) {
    return &connection.application;
  }
  return nullptr;
}

void mergeNetworkConnectionToProcessData(
    const NetworkConnection& connection,
    std::unordered_map<std::string, ProcessInfo>& process_data) {
  const std::string* process_key = resolveProcessKey(connection);
  if (process_key == nullptr) {
    return;
  }

  auto& info = ensureProcessEntry(process_data, *process_key);
  appendEvidenceSource(info, "NetworkEvent");
  appendTimelineArtifact(info, buildNetworkTimelineArtifact(connection));
}

struct RecoveryAnalyzerRef {
  std::string_view      label;
  const IRecoveryAnalyzer* analyzer = nullptr;
};

struct RecoveryStageSlot {
  std::string_view             label;
  std::vector<RecoveryEvidence> evidence;
};

std::vector<RecoveryStageSlot> createRecoveryStageSlots(
    const std::vector<RecoveryAnalyzerRef>& analyzers) {
  std::vector<RecoveryStageSlot> slots;
  slots.reserve(analyzers.size());
  for (const auto& analyzer : analyzers) {
    slots.push_back({analyzer.label, {}});
  }
  return slots;
}

void runRecoveryStageCollectorsInParallel(
    const std::vector<RecoveryAnalyzerRef>& analyzers, const std::string& disk_root,
    const std::shared_ptr<spdlog::logger>& logger,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  struct Task {
    std::size_t index;
    std::future<std::vector<RecoveryEvidence>> future;
  };

  std::vector<Task> tasks;
  tasks.reserve(analyzers.size());

  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    const IRecoveryAnalyzer* ptr = analyzers[i].analyzer;
    tasks.push_back(
        {i, std::async(std::launch::async,
                       [ptr, &disk_root] { return ptr->collect(disk_root); })});
  }

  for (auto& task : tasks) {
    try {
      per_analyzer[task.index].evidence = task.future.get();
    } catch (const std::exception& e) {
      logger->error("Recovery({}): ошибка этапа", per_analyzer[task.index].label);
      logger->debug("Recovery({}) exception: {}", per_analyzer[task.index].label,
                    e.what());
    } catch (...) {
      logger->error("Recovery({}): неизвестная ошибка этапа",
                    per_analyzer[task.index].label);
    }
  }
}

void runRecoveryStageCollectorsSequentially(
    const std::vector<RecoveryAnalyzerRef>& analyzers, const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer) {
  for (std::size_t i = 0; i < analyzers.size(); ++i) {
    per_analyzer[i].evidence = analyzers[i].analyzer->collect(disk_root);
  }
}

void appendRecoverySummaryItem(std::string& summary, const std::string_view label,
                               const std::size_t evidence_count) {
  if (!summary.empty()) {
    summary += ", ";
  }
  summary += label;
  summary.push_back('=');
  summary += std::to_string(evidence_count);
}

std::string mergeRecoveryEvidenceResults(
    std::vector<RecoveryStageSlot>& per_analyzer,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<RecoveryEvidence>& recovery_evidence) {
  std::string summary;
  summary.reserve(per_analyzer.size() * 24);

  for (auto& slot : per_analyzer) {
    appendRecoverySummaryItem(summary, slot.label, slot.evidence.size());
    mergeRecoveryEvidenceToProcessData(slot.evidence, process_data);
    appendMovedVector(recovery_evidence, slot.evidence);
  }

  return summary;
}

}  // namespace

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

    appendEvidenceSource(info, entry.source.empty() ? "Amcache" : entry.source);
    if (!entry.modification_time_str.empty() &&
        entry.modification_time_str != "N/A") {
      info.run_times.push_back(entry.modification_time_str);
      updateProcessTimestampBounds(info, entry.modification_time_str);
    }

    if (entry.is_deleted) {
      appendTamperFlag(info, "amcache_deleted_trace");
    }
    appendTimelineArtifact(
        info, "[" + (entry.source.empty() ? std::string("Amcache")
                                          : entry.source) +
                  "] " + path);
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
    auto& merged = ensureProcessEntry(process_data_, info.filename);
    mergePrefetchProcessInfo(merged, info);
  }

  logger->info("Этап 3/7 завершен: prefetch-процессов={}",
               prefetch_results.size());
}

void WindowsDiskAnalyzer::runEventLogStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 4/7: анализ EventLog");

  const auto run_count_before_eventlog = buildRunCountSnapshot(process_data_);

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.eventlog);
    for (const auto& collector : eventlog_collectors_) {
      collector->collect(disk_root_, process_data_, network_connections_);
    }
  }

  for (auto& [process_key, info] : process_data_) {
    if (shouldAppendEventLogEvidence(run_count_before_eventlog, process_key,
                                     info.run_count)) {
      appendEventLogEvidence(info);
    }

    updateProcessTimestampBoundsFromRunTimes(info);
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
    mergeNetworkConnectionToProcessData(connection, process_data_);
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

  std::vector<RecoveryAnalyzerRef> analyzers;
  analyzers.reserve(recovery_analyzers_.size());
  for (const auto& analyzer : recovery_analyzers_) {
    analyzers.push_back({analyzer.label, analyzer.analyzer.get()});
  }

  auto per_analyzer = createRecoveryStageSlots(analyzers);

  if (run_parallel) {
    logger->info("Recovery: параллельный режим включен (MaxIOWorkers={})",
                 performance_options_.max_io_workers);
    runRecoveryStageCollectorsInParallel(analyzers, disk_root_, logger,
                                         per_analyzer);
  } else {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    runRecoveryStageCollectorsSequentially(analyzers, disk_root_, per_analyzer);
  }

  const std::string summary = mergeRecoveryEvidenceResults(
      per_analyzer, process_data_, recovery_evidence_);

  logger->info("Этап 6/7 завершен: {}", summary);
}

void WindowsDiskAnalyzer::applyGlobalTamperFlags() {
  for (auto& [_, info] : process_data_) {
    for (const auto& global_flag : global_tamper_flags_) {
      appendTamperFlag(info, global_flag);
    }
  }
}

void WindowsDiskAnalyzer::applyTamperRules() {
  if (!tamper_options_.enable_prefetch_missing_rule) {
    return;
  }

  const std::set<std::string> prefetch_names = buildPrefetchFilenameSet(
      disk_root_, config_path_, os_info_.ini_version);
  for (auto& [process_key, info] : process_data_) {
    if (tamper_options_.prefetch_missing_require_process_image &&
        !looksLikeProcessImage(process_key) &&
        !looksLikeProcessImage(info.filename)) {
      continue;
    }

    if (prefetch_names.find(buildPrefetchLookupKey(process_key)) !=
            prefetch_names.end() ||
        prefetch_names.find(buildPrefetchLookupKey(info.filename)) !=
            prefetch_names.end()) {
      continue;
    }

    if (hasAnySource(info, tamper_options_.runtime_sources)) {
      appendTamperFlag(info,
                       "prefetch_missing_but_other_artifacts_present");
    }
  }
}

void WindowsDiskAnalyzer::exportCsv(const std::string& output_path) {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 7/7: экспорт CSV");

  ensureDirectoryExists(output_path);
  CSVExporter::exportToCSV(output_path, autorun_entries_, process_data_,
                           network_connections_, amcache_entries_,
                           recovery_evidence_);
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
  applyTamperRules();
  applyGlobalTamperFlags();
  exportCsv(output_path);

  logger->info("Анализ завершен: процессов={}, сетевых событий={}",
               process_data_.size(), network_connections_.size());
}

}  // namespace WindowsDiskAnalysis
