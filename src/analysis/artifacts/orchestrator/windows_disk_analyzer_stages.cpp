/// @file windows_disk_analyzer_stages.cpp
/// @brief Stage-ориентированная реализация WindowsDiskAnalyzer.

#include "windows_disk_analyzer.hpp"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

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

std::string selectExecutablePathForAmcacheEntry(const AmcacheEntry& entry) {
  const auto pick_if_valid = [](std::string raw_path) -> std::string {
    trim(raw_path);
    if (raw_path.empty()) {
      return {};
    }
    std::ranges::replace(raw_path, '/', '\\');
    if (!PathUtils::isExecutionPathCandidate(raw_path)) {
      return {};
    }
    return raw_path;
  };

  if (std::string path = pick_if_valid(entry.file_path); !path.empty()) {
    return path;
  }
  if (std::string path = pick_if_valid(entry.alternate_path); !path.empty()) {
    return path;
  }
  return {};
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

ProcessInfo& ensureProcessEntry(
    std::unordered_map<std::string, ProcessInfo>& process_data,
    const std::string& process_key) {
  auto& info = process_data[process_key];
  if (info.filename.empty()) {
    info.filename = process_key;
  }
  return info;
}

ProcessInfo& ensureProcessEntry(
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::string& process_key) {
  auto& info = process_data[process_key];
  if (info.filename.empty()) {
    info.filename = std::move(process_key);
  }
  return info;
}

void appendPrefetchTimeline(ProcessInfo& merged,
                            const ProcessInfo& prefetch_info) {
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

}  // namespace

void WindowsDiskAnalyzer::runAutorunStage() {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 1/7: анализ автозагрузки");

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.autorun);
    autorun_entries_ = autorun_analyzer_->collect(disk_root_);
  }

  for (const auto& entry : autorun_entries_) {
    if (entry.path.empty()) {
      continue;
    }

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
    const std::string path = selectExecutablePathForAmcacheEntry(entry);
    if (path.empty()) {
      continue;
    }

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

  logger->info("Этап 4/7 завершен: {} сетевых событий",
               network_connections_.size());
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

  logger->info("Этап 5/7 завершен: {} процессов в агрегате",
               process_data_.size());
}

}  // namespace WindowsDiskAnalysis
