/// @file csv_exporter.cpp
/// @brief Реализация экспорта артефактов в единый record-level CSV.

#include "csv_exporter.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/recovery_contract.hpp"
#include "common/path_utils.hpp"
#include "common/utils.hpp"
#include "csv_exporter_utils.hpp"
#include "errors/csv_export_exception.hpp"

using namespace WindowsDiskAnalysis::CsvExporterUtils;

namespace {

constexpr char kCsvDelimiter = ';';
constexpr std::string_view kListSeparator = " | ";

constexpr std::string_view kUnifiedCsvHeader =
    "record_id;source;artifact_type;path_or_key;timestamp_utc;is_recovered;"
    "recovered_from;host_hint;user_hint;raw_details\n";

constexpr std::string_view kRecoveryCsvHeader =
    "ExecutablePath;Source;RecoveredFrom;Timestamp;Details\n";

struct UnifiedCsvRow {
  std::string source;
  std::string artifact_type;
  std::string path_or_key;
  std::string timestamp_utc;
  std::string is_recovered;
  std::string recovered_from;
  std::string host_hint;
  std::string user_hint;
  std::string raw_details;
};

std::string escapeCsvField(std::string_view value) {
  if (value.empty()) return {};

  auto sanitizeUtf8 = [](std::string_view raw) {
    std::string sanitized;
    sanitized.reserve(raw.size());

    for (std::size_t i = 0; i < raw.size();) {
      const unsigned char c = static_cast<unsigned char>(raw[i]);
      if (c < 0x80) {
        if (c == '\0') {
          ++i;
          continue;
        }
        if (c == '\n' || c == '\r' || c == '\t') {
          sanitized.push_back(' ');
        } else if (std::iscntrl(c) != 0) {
          sanitized.push_back(' ');
        } else {
          sanitized.push_back(static_cast<char>(c));
        }
        ++i;
        continue;
      }

      std::size_t sequence_size = 0;
      if ((c & 0xE0U) == 0xC0U) {
        sequence_size = (c >= 0xC2U) ? 2U : 0U;
      } else if ((c & 0xF0U) == 0xE0U) {
        sequence_size = 3U;
      } else if ((c & 0xF8U) == 0xF0U) {
        sequence_size = (c <= 0xF4U) ? 4U : 0U;
      }

      if (sequence_size == 0 || i + sequence_size > raw.size()) {
        sanitized.push_back('?');
        ++i;
        continue;
      }

      const auto b1 =
          static_cast<unsigned char>(raw[i + 1]);
      bool valid = (b1 & 0xC0U) == 0x80U;
      for (std::size_t j = 2; valid && j < sequence_size; ++j) {
        const auto continuation =
            static_cast<unsigned char>(raw[i + j]);
        valid = (continuation & 0xC0U) == 0x80U;
      }

      if (valid && sequence_size == 3) {
        if (c == 0xE0U && b1 < 0xA0U) valid = false;
        if (c == 0xEDU && b1 >= 0xA0U) valid = false;
      }
      if (valid && sequence_size == 4) {
        if (c == 0xF0U && b1 < 0x90U) valid = false;
        if (c == 0xF4U && b1 >= 0x90U) valid = false;
      }

      if (!valid) {
        sanitized.push_back('?');
        ++i;
        continue;
      }

      sanitized.append(raw.substr(i, sequence_size));
      i += sequence_size;
    }

    return sanitized;
  };

  const std::string sanitized = sanitizeUtf8(value);
  if (sanitized.empty()) {
    return {};
  }

  std::string result;
  result.reserve(sanitized.size() + 2);
  result.push_back('"');

  for (const char c : sanitized) {
    if (c == '"') {
      result.append("\"\"");
    } else {
      result.push_back(c);
    }
  }

  result.push_back('"');
  return result;
}

void writeUnifiedCsvHeader(std::ofstream& file) { file << kUnifiedCsvHeader; }

void writeRecoveryCsvHeader(std::ofstream& file) { file << kRecoveryCsvHeader; }

template <typename Container>
std::vector<std::string> toSortedUniqueStrings(const Container& values) {
  std::vector<std::string> result;
  result.reserve(values.size());
  for (const auto& value : values) {
    if (!value.empty()) {
      result.emplace_back(value);
    }
  }
  sortAndUnique(result);
  return result;
}

std::string joinStrings(const std::vector<std::string>& values) {
  if (values.empty()) {
    return {};
  }

  std::size_t total_size = (values.size() - 1) * kListSeparator.size();
  for (const auto& value : values) {
    total_size += value.size();
  }

  std::string out;
  out.reserve(total_size);
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      out.append(kListSeparator);
    }
    out.append(values[i]);
  }
  return out;
}

std::string normalizeSourceOrFallback(std::string source,
                                      std::string_view fallback) {
  source = normalizeEvidenceSource(std::move(source));
  if (!source.empty()) {
    return source;
  }
  return std::string(fallback);
}

std::string resolveArtifactTypeBySource(std::string source,
                                        std::string_view fallback) {
  source = normalizeEvidenceSource(std::move(source));
  if (source.empty()) {
    return std::string(fallback);
  }

  static const std::unordered_map<std::string, std::string_view>
      kArtifactTypeBySource = {
          {"Process", "process_evidence"},
          {"Prefetch", "prefetch_execution"},
          {"EventLog", "eventlog_execution"},
          {"SecurityContext", "security_context"},
          {"Security4688", "security_event_4688"},
          {"Security4624", "security_event_4624"},
          {"Security4672", "security_event_4672"},
          {"SecurityCorrelation", "security_correlation"},
          {"Autorun", "autorun_entry"},
          {"Amcache", "amcache_entry"},
          {"NetworkEvent", "network_connection"},
          {"UserAssist", "userassist_entry"},
          {"RunMRU", "runmru_entry"},
          {"BAM", "bam_execution"},
          {"DAM", "dam_execution"},
          {"ShimCache", "shimcache_entry"},
          {"TaskScheduler", "task_scheduler_entry"},
          {"LNKRecent", "lnk_recent_entry"},
          {"JumpList", "jump_list_entry"},
          {"PSConsoleHistory", "powershell_history_entry"},
          {"SRUM", "srum_entry"},
          {"USN", "usn_recovery_evidence"},
          {"$LogFile", "logfile_recovery_evidence"},
          {"VSS", "vss_recovery_evidence"},
          {"Pagefile", "pagefile_recovery_evidence"},
          {"Memory", "memory_recovery_evidence"},
          {"Unallocated", "unallocated_recovery_evidence"},
          {"NTFSMetadata", "ntfs_recovery_evidence"},
          {"Registry", "registry_recovery_evidence"},
          {"RegistryLog", "registry_recovery_evidence"},
          {"Hiber", "hiber_recovery_evidence"},
          {"SignatureScan", "signature_recovery_evidence"},
          {"TSK", "tsk_recovery_evidence"},
      };

  const auto it = kArtifactTypeBySource.find(source);
  if (it != kArtifactTypeBySource.end()) {
    return std::string(it->second);
  }
  return std::string(fallback);
}

std::string normalizePathOrKeep(const std::string& path) {
  if (path.empty()) {
    return {};
  }
  std::string normalized = normalizePath(path);
  if (!normalized.empty()) {
    return normalized;
  }
  return path;
}

std::string extractHostHintFromPathOrKey(const std::string& path_or_key) {
  if (path_or_key.size() < 3) {
    return {};
  }

  const auto is_slash = [](const char c) { return c == '\\' || c == '/'; };
  if (!is_slash(path_or_key[0]) || !is_slash(path_or_key[1])) {
    return {};
  }

  std::size_t host_start = 2;
  while (host_start < path_or_key.size() && is_slash(path_or_key[host_start])) {
    ++host_start;
  }
  if (host_start >= path_or_key.size()) {
    return {};
  }

  std::size_t host_end = host_start;
  while (host_end < path_or_key.size() && !is_slash(path_or_key[host_end])) {
    ++host_end;
  }

  if (host_end <= host_start) {
    return {};
  }
  return path_or_key.substr(host_start, host_end - host_start);
}

void appendDetail(std::string& details, std::string_view key,
                  std::string value) {
  trim(value);
  if (value.empty()) {
    return;
  }
  if (!details.empty()) {
    details.append(kListSeparator);
  }
  details.append(key);
  details.push_back('=');
  details.append(value);
}

bool startsWithIsoUtcPrefix(const std::string& value) {
  if (value.size() < 19) {
    return false;
  }

  auto is_digit = [&](const std::size_t index) {
    return std::isdigit(static_cast<unsigned char>(value[index])) != 0;
  };

  return is_digit(0) && is_digit(1) && is_digit(2) && is_digit(3) &&
         value[4] == '-' && is_digit(5) && is_digit(6) && value[7] == '-' &&
         is_digit(8) && is_digit(9) && value[10] == ' ' && is_digit(11) &&
         is_digit(12) && value[13] == ':' && is_digit(14) && is_digit(15) &&
         value[16] == ':' && is_digit(17) && is_digit(18);
}

std::string extractTimelineTimestamp(const std::string& timeline) {
  if (!startsWithIsoUtcPrefix(timeline)) {
    return {};
  }
  return timeline.substr(0, 19);
}

std::string stripTimelineTimestamp(const std::string& timeline) {
  if (!startsWithIsoUtcPrefix(timeline)) {
    return timeline;
  }
  if (timeline.size() > 20 && timeline[19] == ' ') {
    return timeline.substr(20);
  }
  return timeline.substr(19);
}

std::string extractTimelineSource(const std::string& timeline) {
  const std::string without_timestamp = stripTimelineTimestamp(timeline);
  const std::size_t open = without_timestamp.find('[');
  if (open == std::string::npos) {
    return {};
  }
  const std::size_t close = without_timestamp.find(']', open + 1);
  if (close == std::string::npos || close <= open + 1) {
    return {};
  }
  return without_timestamp.substr(open + 1, close - open - 1);
}

bool isRecoverySource(const std::string& source) {
  const std::string lowered = toLowerAscii(source);
  return lowered == "usn" || lowered == "$logfile" || lowered == "vss" ||
         lowered == "pagefile" || lowered == "memory" ||
         lowered == "unallocated" || lowered.find("ntfs") != std::string::npos ||
         lowered.find("hiber") != std::string::npos ||
         lowered.find("signature") != std::string::npos ||
         lowered.find("registry") != std::string::npos;
}

void appendUnifiedRow(std::vector<UnifiedCsvRow>& rows, UnifiedCsvRow row) {
  if (row.source.empty()) {
    row.source = "Unknown";
  }
  if (row.artifact_type.empty()) {
    row.artifact_type = "unknown";
  }
  if (row.is_recovered.empty()) {
    row.is_recovered = "0";
  }
  if (row.host_hint.empty()) {
    row.host_hint = extractHostHintFromPathOrKey(row.path_or_key);
  }
  rows.push_back(std::move(row));
}

std::string selectExecutablePathForAmcache(
    const WindowsDiskAnalysis::AmcacheEntry& entry) {
  const auto pick_if_valid = [](const std::string& raw_path) -> std::string {
    if (raw_path.empty()) {
      return {};
    }
    const std::string normalized = normalizePath(raw_path);
    if (normalized.empty() ||
        !PathUtils::isExecutionPathCandidate(normalized)) {
      return {};
    }
    return normalized;
  };

  if (std::string path = pick_if_valid(entry.file_path); !path.empty()) {
    return path;
  }
  if (std::string path = pick_if_valid(entry.alternate_path); !path.empty()) {
    return path;
  }
  return {};
}

std::string buildProcessBaseDetails(const WindowsDiskAnalysis::ProcessInfo& info) {
  std::string details;
  appendDetail(details, "run_count", std::to_string(info.run_count));
  appendDetail(details, "command", info.command);
  appendDetail(details, "first_seen_utc", info.first_seen_utc);
  appendDetail(details, "last_seen_utc", info.last_seen_utc);
  appendDetail(details, "run_times", joinStrings(toSortedUniqueStrings(info.run_times)));
  appendDetail(details, "user_sids", joinStrings(toSortedUniqueStrings(info.user_sids)));
  appendDetail(details, "logon_ids", joinStrings(toSortedUniqueStrings(info.logon_ids)));
  appendDetail(details, "logon_types", joinStrings(toSortedUniqueStrings(info.logon_types)));
  appendDetail(details, "elevation_type", info.elevation_type);
  appendDetail(details, "elevated_token", info.elevated_token);
  appendDetail(details, "integrity_level", info.integrity_level);
  appendDetail(details, "privileges", joinStrings(toSortedUniqueStrings(info.privileges)));
  return details;
}

std::string chooseProcessTimestamp(const WindowsDiskAnalysis::ProcessInfo& info) {
  if (!info.first_seen_utc.empty()) {
    return info.first_seen_utc;
  }
  const std::vector<std::string> run_times = toSortedUniqueStrings(info.run_times);
  if (!run_times.empty()) {
    return run_times.front();
  }
  return {};
}

void appendAutorunRows(
    std::vector<UnifiedCsvRow>& rows,
    const std::vector<WindowsDiskAnalysis::AutorunEntry>& autorun_entries) {
  std::vector<WindowsDiskAnalysis::AutorunEntry> sorted = autorun_entries;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::tie(lhs.path, lhs.location, lhs.name, lhs.command) <
                     std::tie(rhs.path, rhs.location, rhs.name, rhs.command);
            });

  for (const auto& entry : sorted) {
    std::string details;
    appendDetail(details, "name", entry.name);
    appendDetail(details, "location", entry.location);
    appendDetail(details, "command", entry.command);

    appendUnifiedRow(rows, {.source = "Autorun",
                            .artifact_type = "autorun_entry",
                            .path_or_key = normalizePathOrKeep(entry.path),
                            .is_recovered = "0",
                            .raw_details = std::move(details)});
  }
}

void appendProcessRows(
    std::vector<UnifiedCsvRow>& rows,
    const std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo>&
        process_data) {
  std::vector<std::string> keys;
  keys.reserve(process_data.size());
  for (const auto& [key, _] : process_data) {
    keys.push_back(key);
  }
  std::sort(keys.begin(), keys.end());

  for (const auto& key : keys) {
    const auto it = process_data.find(key);
    if (it == process_data.end()) {
      continue;
    }
    const auto& info = it->second;

    std::string path_or_key = normalizePathOrKeep(key);
    if (path_or_key.empty()) {
      path_or_key = normalizePathOrKeep(info.filename);
    }

    std::vector<std::string> evidence_sources = toSortedUniqueStrings(info.evidence_sources);
    for (auto& source : evidence_sources) {
      source = normalizeSourceOrFallback(std::move(source), "Process");
    }
    sortAndUnique(evidence_sources);
    if (evidence_sources.empty()) {
      if (!info.metrics.empty() || !info.volumes.empty()) {
        evidence_sources.emplace_back("Prefetch");
      } else if (info.run_count > 0 || !info.run_times.empty()) {
        evidence_sources.emplace_back("EventLog");
      } else {
        evidence_sources.emplace_back("Process");
      }
    }

    std::string base_details = buildProcessBaseDetails(info);
    const std::string user_hint = joinStrings(toSortedUniqueStrings(info.users));
    const std::string process_timestamp = chooseProcessTimestamp(info);

    for (const auto& source : evidence_sources) {
      std::string details = base_details;
      appendDetail(details, "evidence_source", source);
      const std::string artifact_type =
          resolveArtifactTypeBySource(source, "process_evidence");

      appendUnifiedRow(rows, {.source = source,
                              .artifact_type = artifact_type,
                              .path_or_key = path_or_key,
                              .timestamp_utc = process_timestamp,
                              .is_recovered = "0",
                              .user_hint = user_hint,
                              .raw_details = std::move(details)});
    }

    std::vector<std::string> recovered_from = toSortedUniqueStrings(info.recovered_from);
    for (auto& source : recovered_from) {
      source = normalizeSourceOrFallback(std::move(source), "Recovery");
    }
    sortAndUnique(recovered_from);
    for (const auto& source : recovered_from) {
      std::string details = base_details;
      appendDetail(details, "recovered_marker", source);
      appendUnifiedRow(rows, {.source = source,
                              .artifact_type = "process_recovery_marker",
                              .path_or_key = path_or_key,
                              .timestamp_utc = process_timestamp,
                              .is_recovered = "1",
                              .recovered_from = source,
                              .user_hint = user_hint,
                              .raw_details = std::move(details)});
    }

    std::vector<std::string> timeline = toSortedUniqueStrings(info.timeline_artifacts);
    for (const auto& timeline_entry : timeline) {
      std::string source = normalizeSourceOrFallback(
          extractTimelineSource(timeline_entry), "Timeline");
      const std::string timestamp = [&]() {
        const std::string extracted = extractTimelineTimestamp(timeline_entry);
        return extracted.empty() ? process_timestamp : extracted;
      }();
      const bool recovered = isRecoverySource(source);
      const std::string artifact_type =
          resolveArtifactTypeBySource(source, "timeline_artifact");

      appendUnifiedRow(rows, {.source = source,
                              .artifact_type = artifact_type,
                              .path_or_key = path_or_key,
                              .timestamp_utc = timestamp,
                              .is_recovered = recovered ? "1" : "0",
                              .recovered_from = recovered ? source : std::string(),
                              .user_hint = user_hint,
                              .raw_details = timeline_entry});
    }
  }
}

void appendNetworkRows(
    std::vector<UnifiedCsvRow>& rows,
    const std::vector<WindowsDiskAnalysis::NetworkConnection>&
        network_connections) {
  std::vector<WindowsDiskAnalysis::NetworkConnection> sorted =
      network_connections;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::tie(lhs.timestamp, lhs.application, lhs.process_name,
                              lhs.process_id, lhs.event_id, lhs.source_ip,
                              lhs.source_port, lhs.dest_ip, lhs.dest_port) <
                     std::tie(rhs.timestamp, rhs.application, rhs.process_name,
                              rhs.process_id, rhs.event_id, rhs.source_ip,
                              rhs.source_port, rhs.dest_ip, rhs.dest_port);
            });

  for (const auto& conn : sorted) {
    std::string details;
    appendDetail(details, "event_id", std::to_string(conn.event_id));
    appendDetail(details, "pid", std::to_string(conn.process_id));
    appendDetail(details, "process_name", conn.process_name);
    appendDetail(details, "source_ip", conn.source_ip);
    appendDetail(details, "source_port", std::to_string(conn.source_port));
    appendDetail(details, "dest_ip", conn.dest_ip);
    appendDetail(details, "dest_port", std::to_string(conn.dest_port));
    appendDetail(details, "protocol", conn.protocol);
    appendDetail(details, "direction", conn.direction);
    appendDetail(details, "action", conn.action);

    std::string path_or_key = normalizePathOrKeep(conn.application);
    if (path_or_key.empty()) {
      path_or_key = normalizePathOrKeep(conn.process_name);
    }
    if (path_or_key.empty() && conn.process_id > 0) {
      path_or_key = "pid:" + std::to_string(conn.process_id);
    }

    appendUnifiedRow(rows, {.source = "NetworkEvent",
                            .artifact_type = "network_connection",
                            .path_or_key = std::move(path_or_key),
                            .timestamp_utc = conn.timestamp,
                            .is_recovered = "0",
                            .host_hint = conn.source_ip,
                            .raw_details = std::move(details)});
  }
}

void appendAmcacheRows(
    std::vector<UnifiedCsvRow>& rows,
    const std::vector<WindowsDiskAnalysis::AmcacheEntry>& amcache_entries) {
  std::vector<WindowsDiskAnalysis::AmcacheEntry> sorted = amcache_entries;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::tie(lhs.file_path, lhs.alternate_path,
                              lhs.modification_time_str, lhs.install_time_str,
                              lhs.file_hash, lhs.name) <
                     std::tie(rhs.file_path, rhs.alternate_path,
                              rhs.modification_time_str, rhs.install_time_str,
                              rhs.file_hash, rhs.name);
            });

  for (const auto& entry : sorted) {
    std::string details;
    appendDetail(details, "name", entry.name);
    appendDetail(details, "version", entry.version);
    appendDetail(details, "file_hash", entry.file_hash);
    appendDetail(details, "publisher", entry.publisher);
    appendDetail(details, "description", entry.description);
    if (entry.file_size > 0) {
      appendDetail(details, "file_size", std::to_string(entry.file_size));
    }
    appendDetail(details, "is_deleted", entry.is_deleted ? "1" : "0");
    appendDetail(details, "alternate_path", normalizePathOrKeep(entry.alternate_path));
    appendDetail(details, "install_time_utc", entry.install_time_str);

    const std::string timestamp = !entry.modification_time_str.empty()
                                      ? entry.modification_time_str
                                      : entry.install_time_str;
    const std::string path_or_key = [&]() {
      const std::string selected = selectExecutablePathForAmcache(entry);
      if (!selected.empty()) {
        return selected;
      }
      const std::string main_path = normalizePathOrKeep(entry.file_path);
      if (!main_path.empty()) {
        return main_path;
      }
      return normalizePathOrKeep(entry.alternate_path);
    }();

    appendUnifiedRow(rows, {.source = normalizeSourceOrFallback(
                                entry.source.empty() ? "Amcache" : entry.source,
                                "Amcache"),
                            .artifact_type = "amcache_entry",
                            .path_or_key = path_or_key,
                            .timestamp_utc = timestamp,
                            .is_recovered = "0",
                            .raw_details = std::move(details)});
  }
}

void appendRecoveryRows(
    std::vector<UnifiedCsvRow>& rows,
    const std::vector<WindowsDiskAnalysis::RecoveryEvidence>& recovery_evidence) {
  std::vector<WindowsDiskAnalysis::RecoveryEvidence> sorted = recovery_evidence;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::tie(lhs.executable_path, lhs.source, lhs.recovered_from,
                              lhs.timestamp, lhs.details) <
                     std::tie(rhs.executable_path, rhs.source, rhs.recovered_from,
                              rhs.timestamp, rhs.details);
            });

  for (const auto& entry : sorted) {
    const std::string source =
        normalizeSourceOrFallback(entry.source, "Recovery");
    const std::string recovered_from =
        entry.recovered_from.empty() ? source : entry.recovered_from;

    appendUnifiedRow(rows, {.source = source,
                            .artifact_type = "recovery_evidence",
                            .path_or_key = normalizePathOrKeep(entry.executable_path),
                            .timestamp_utc = entry.timestamp,
                            .is_recovered = "1",
                            .recovered_from = recovered_from,
                            .raw_details = entry.details});
  }
}

bool sameUnifiedRow(const UnifiedCsvRow& lhs, const UnifiedCsvRow& rhs) {
  return std::tie(lhs.source, lhs.artifact_type, lhs.path_or_key,
                  lhs.timestamp_utc, lhs.is_recovered, lhs.recovered_from,
                  lhs.host_hint, lhs.user_hint, lhs.raw_details) ==
         std::tie(rhs.source, rhs.artifact_type, rhs.path_or_key,
                  rhs.timestamp_utc, rhs.is_recovered, rhs.recovered_from,
                  rhs.host_hint, rhs.user_hint, rhs.raw_details);
}

void finalizeUnifiedRows(std::vector<UnifiedCsvRow>& rows) {
  std::sort(rows.begin(), rows.end(),
            [](const UnifiedCsvRow& lhs, const UnifiedCsvRow& rhs) {
              return std::tie(lhs.source, lhs.artifact_type, lhs.path_or_key,
                              lhs.timestamp_utc, lhs.is_recovered,
                              lhs.recovered_from, lhs.host_hint, lhs.user_hint,
                              lhs.raw_details) <
                     std::tie(rhs.source, rhs.artifact_type, rhs.path_or_key,
                              rhs.timestamp_utc, rhs.is_recovered,
                              rhs.recovered_from, rhs.host_hint, rhs.user_hint,
                              rhs.raw_details);
            });
  rows.erase(std::unique(rows.begin(), rows.end(), sameUnifiedRow), rows.end());
}

void writeUnifiedRows(std::ofstream& file, const std::vector<UnifiedCsvRow>& rows) {
  std::size_t record_index = 1;
  for (const auto& row : rows) {
    const std::string record_id = "rec-" + std::to_string(record_index++);
    file << escapeCsvField(record_id) << kCsvDelimiter
         << escapeCsvField(row.source) << kCsvDelimiter
         << escapeCsvField(row.artifact_type) << kCsvDelimiter
         << escapeCsvField(row.path_or_key) << kCsvDelimiter
         << escapeCsvField(row.timestamp_utc) << kCsvDelimiter
         << escapeCsvField(row.is_recovered) << kCsvDelimiter
         << escapeCsvField(row.recovered_from) << kCsvDelimiter
         << escapeCsvField(row.host_hint) << kCsvDelimiter
         << escapeCsvField(row.user_hint) << kCsvDelimiter
         << escapeCsvField(row.raw_details) << '\n';
  }
}

std::filesystem::path buildRecoveryOutputPath(
    const std::string& output_path, const std::string& explicit_recovery_path) {
  if (!explicit_recovery_path.empty()) {
    return explicit_recovery_path;
  }

  const std::filesystem::path base_path(output_path);
  const std::filesystem::path parent = base_path.parent_path();
  const std::string stem = base_path.stem().empty()
                               ? base_path.filename().string()
                               : base_path.stem().string();
  const std::string extension =
      base_path.has_extension() ? base_path.extension().string() : ".csv";
  return parent / (stem + "_recovery" + extension);
}

void writeRecoveryRows(std::ofstream& file,
                       const std::vector<WindowsDiskAnalysis::RecoveryEvidence>&
                           recovery_evidence) {
  for (const auto& entry : recovery_evidence) {
    file << escapeCsvField(entry.executable_path) << kCsvDelimiter
         << escapeCsvField(entry.source) << kCsvDelimiter
         << escapeCsvField(entry.recovered_from) << kCsvDelimiter
         << escapeCsvField(entry.timestamp) << kCsvDelimiter
         << escapeCsvField(entry.details) << '\n';
  }
}

void exportRecoveryCsv(
    const std::string& output_path,
    const std::vector<WindowsDiskAnalysis::RecoveryEvidence>& recovery_evidence,
    const WindowsDiskAnalysis::CSVExportOptions& options) {
  std::vector<WindowsDiskAnalysis::RecoveryEvidence> sorted = recovery_evidence;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::tie(lhs.executable_path, lhs.source, lhs.recovered_from,
                              lhs.timestamp, lhs.details) <
                     std::tie(rhs.executable_path, rhs.source, rhs.recovered_from,
                              rhs.timestamp, rhs.details);
            });
  sorted.erase(std::unique(sorted.begin(), sorted.end(),
                           [](const auto& lhs, const auto& rhs) {
                             return std::tie(lhs.executable_path, lhs.source,
                                             lhs.recovered_from, lhs.timestamp,
                                             lhs.details) ==
                                    std::tie(rhs.executable_path, rhs.source,
                                             rhs.recovered_from, rhs.timestamp,
                                             rhs.details);
                           }),
               sorted.end());

  const std::filesystem::path recovery_output_path =
      buildRecoveryOutputPath(output_path, options.recovery_output_path);
  std::ofstream recovery_file(recovery_output_path, std::ios::binary);
  if (!recovery_file.is_open()) {
    throw WindowsDiskAnalysis::FileOpenException(recovery_output_path.string());
  }

  recovery_file.write("\xEF\xBB\xBF", 3);
  writeRecoveryCsvHeader(recovery_file);
  writeRecoveryRows(recovery_file, sorted);
}

}  // namespace

namespace WindowsDiskAnalysis {

void CSVExporter::exportToCSV(
    const std::string& output_path,
    const std::vector<AutorunEntry>& autorun_entries,
    const std::unordered_map<std::string, ProcessInfo>& process_data,
    const std::vector<NetworkConnection>& network_connections,
    const std::vector<AmcacheEntry>& amcache_entries,
    const std::vector<RecoveryEvidence>& recovery_evidence,
    const CSVExportOptions& options) {
  std::vector<RecoveryEvidence> normalized_recovery_evidence = recovery_evidence;
  RecoveryContract::canonicalizeRecoveryEvidence(normalized_recovery_evidence);

  std::ofstream file(output_path, std::ios::binary);
  if (!file.is_open()) {
    throw FileOpenException(output_path);
  }

  try {
    file.write("\xEF\xBB\xBF", 3);
    writeUnifiedCsvHeader(file);

    std::vector<UnifiedCsvRow> rows;
    rows.reserve(autorun_entries.size() + process_data.size() +
                 network_connections.size() + amcache_entries.size() +
                 normalized_recovery_evidence.size());

    appendAutorunRows(rows, autorun_entries);
    appendProcessRows(rows, process_data);
    appendNetworkRows(rows, network_connections);
    appendAmcacheRows(rows, amcache_entries);
    appendRecoveryRows(rows, normalized_recovery_evidence);
    finalizeUnifiedRows(rows);
    writeUnifiedRows(file, rows);
  } catch (const std::exception& e) {
    throw CsvExportException(std::string("Ошибка при экспорте данных: ") +
                             e.what());
  }

  if (options.export_recovery_csv) {
    exportRecoveryCsv(output_path, normalized_recovery_evidence, options);
  }
}

}  // namespace WindowsDiskAnalysis
