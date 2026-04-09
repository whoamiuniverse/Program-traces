/// @file security_context_analyzer.cpp
/// @brief Реализация корреляции 4688/4624/4672 из Security Event Log.

#include "security_context_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {
namespace {

struct LogonSessionRecord {
  std::string timestamp;
  std::optional<int64_t> epoch_seconds;
  std::string logon_id_text;
  std::optional<uint64_t> logon_id;
  std::string user;
  std::string user_sid;
  std::string logon_type;
  std::string elevated_token;
};

struct PrivilegedLogonRecord {
  std::string timestamp;
  std::optional<int64_t> epoch_seconds;
  std::string logon_id_text;
  std::optional<uint64_t> logon_id;
  std::vector<std::string> privileges;
};

struct ProcessCreationRecord {
  std::string timestamp;
  std::optional<int64_t> epoch_seconds;
  uint32_t pid = 0;
  std::string process_path;
  std::string command_line;
  std::string logon_id_text;
  std::optional<uint64_t> logon_id;
  std::string user;
  std::string user_sid;
  std::string elevation_type;
  std::string elevated_token;
  std::string integrity_level;
};

constexpr std::string_view kSecurityContextSection = "SecurityContext";
constexpr std::string_view kExecutionArtifactsSection = "ExecutionArtifacts";
constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

std::string formatEventTimestamp(const uint64_t raw_timestamp) {
  if (raw_timestamp >= kFiletimeUnixEpoch &&
      raw_timestamp <= kMaxReasonableFiletime) {
    return filetimeToString(raw_timestamp);
  }
  return convert_run_times(raw_timestamp);
}

const std::string* findDataValue(
    const std::unordered_map<std::string, std::string>& data,
    const std::initializer_list<std::string_view>& keys) {
  for (const std::string_view key : keys) {
    if (const auto it = data.find(std::string(key)); it != data.end()) {
      return &it->second;
    }
  }
  return nullptr;
}

std::optional<uint32_t> parseUInt32Flexible(std::string raw_value) {
  trim(raw_value);
  if (raw_value.empty()) return std::nullopt;

  uint32_t parsed_value = 0;
  if (tryParseUInt32(raw_value, parsed_value)) {
    return parsed_value;
  }

  try {
    const unsigned long parsed_long = std::stoul(raw_value, nullptr, 0);
    if (parsed_long <= std::numeric_limits<uint32_t>::max()) {
      return static_cast<uint32_t>(parsed_long);
    }
  } catch (...) {
  }

  return std::nullopt;
}

std::optional<uint64_t> parseUInt64Flexible(std::string raw_value) {
  trim(raw_value);
  if (raw_value.empty()) return std::nullopt;

  try {
    std::size_t parsed_length = 0;
    const unsigned long long parsed = std::stoull(raw_value, &parsed_length, 0);
    if (parsed_length == raw_value.size()) {
      return static_cast<uint64_t>(parsed);
    }
  } catch (...) {
  }

  return std::nullopt;
}

std::optional<int64_t> parseTimestampToEpoch(const std::string& timestamp) {
  if (!EvidenceUtils::isTimestampLike(timestamp)) return std::nullopt;

  std::tm time_value{};
  std::istringstream stream(timestamp);
  stream >> std::get_time(&time_value, "%Y-%m-%d %H:%M:%S");
  if (stream.fail()) return std::nullopt;

#if defined(_WIN32)
  const time_t epoch = _mkgmtime(&time_value);
#else
  const time_t epoch = timegm(&time_value);
#endif
  if (epoch == static_cast<time_t>(-1)) return std::nullopt;
  return static_cast<int64_t>(epoch);
}

std::string normalizeLogonType(std::string raw_type) {
  trim(raw_type);
  if (raw_type.empty()) return {};

  const auto parsed = parseUInt32Flexible(raw_type);
  if (!parsed.has_value()) return raw_type;

  switch (*parsed) {
    case 2:
      return "2(Interactive)";
    case 3:
      return "3(Network)";
    case 4:
      return "4(Batch)";
    case 5:
      return "5(Service)";
    case 7:
      return "7(Unlock)";
    case 8:
      return "8(NetworkCleartext)";
    case 9:
      return "9(NewCredentials)";
    case 10:
      return "10(RemoteInteractive)";
    case 11:
      return "11(CachedInteractive)";
    default:
      return std::to_string(*parsed);
  }
}

std::string normalizeElevationType(std::string raw_type) {
  trim(raw_type);
  const std::string lowered = to_lower(raw_type);
  if (lowered.empty()) return {};
  if (lowered == "%%1936" || lowered == "1") return "TokenElevationTypeDefault";
  if (lowered == "%%1937" || lowered == "2") return "TokenElevationTypeFull";
  if (lowered == "%%1938" || lowered == "3") return "TokenElevationTypeLimited";
  return raw_type;
}

std::string normalizeElevatedToken(std::string raw_value) {
  trim(raw_value);
  const std::string lowered = to_lower(raw_value);
  if (lowered.empty()) return {};
  if (lowered == "%%1842" || lowered == "yes" || lowered == "true" ||
      lowered == "1") {
    return "Yes";
  }
  if (lowered == "%%1843" || lowered == "no" || lowered == "false" ||
      lowered == "0") {
    return "No";
  }
  return raw_value;
}

std::string normalizeIntegrityLevel(std::string raw_value) {
  trim(raw_value);
  const std::string lowered = to_lower(raw_value);
  if (lowered.empty()) return {};

  if (lowered == "s-1-16-0") return "Untrusted";
  if (lowered == "s-1-16-4096") return "Low";
  if (lowered == "s-1-16-8192") return "Medium";
  if (lowered == "s-1-16-8448") return "MediumPlus";
  if (lowered == "s-1-16-12288") return "High";
  if (lowered == "s-1-16-16384") return "System";
  if (lowered == "s-1-16-20480") return "ProtectedProcess";
  return raw_value;
}

std::vector<std::string> parsePrivileges(std::string raw_privileges) {
  trim(raw_privileges);
  if (raw_privileges.empty() || raw_privileges == "-") return {};

  for (char& ch : raw_privileges) {
    if (ch == ',' || ch == ';' || ch == '|' || ch == '\n' || ch == '\t') {
      ch = ' ';
    }
  }

  std::vector<std::string> privileges;
  std::istringstream stream(raw_privileges);
  std::string token;
  while (stream >> token) {
    trim(token);
    if (!token.empty() && token != "-") {
      EvidenceUtils::appendUniqueToken(privileges, token);
    }
  }
  return privileges;
}

std::string buildUser(const std::string* domain, const std::string* user) {
  if (user == nullptr) return {};

  std::string user_value = trim_copy(*user);
  if (user_value.empty() || user_value == "-") return {};

  if (domain != nullptr) {
    std::string domain_value = trim_copy(*domain);
    if (!domain_value.empty() && domain_value != "-" &&
        to_lower(domain_value) != "n/a") {
      user_value = domain_value + "\\" + user_value;
    }
  }
  return user_value;
}

std::string normalizeProcessPath(std::string process_path) {
  trim(process_path);
  if (starts_with(process_path, "\\??\\")) {
    process_path.erase(0, 4);
  }

  if (!process_path.empty() && process_path.front() == '"') {
    process_path.erase(process_path.begin());
  }
  if (!process_path.empty() && process_path.back() == '"') {
    process_path.pop_back();
  }

  std::ranges::replace(process_path, '/', '\\');
  trim(process_path);
  return process_path;
}

std::string toCanonicalLogonId(const std::optional<uint64_t>& logon_id,
                               const std::string& fallback_text) {
  if (!logon_id.has_value()) return trim_copy(fallback_text);

  std::ostringstream stream;
  stream << "0x" << std::uppercase << std::hex << *logon_id;
  return stream.str();
}

std::vector<uint32_t> parseEventIds(std::string raw_ids) {
  std::vector<uint32_t> ids;
  for (std::string token : split(raw_ids, ',')) {
    trim(token);
    if (token.empty()) continue;
    if (const auto parsed = parseUInt32Flexible(token); parsed.has_value()) {
      ids.push_back(*parsed);
    }
  }
  return ids;
}

int64_t absoluteDifference(const int64_t left, const int64_t right) {
  return (left >= right) ? (left - right) : (right - left);
}

template <typename TRecord>
const TRecord* findNearestByTime(const std::vector<TRecord>& records,
                                 const std::optional<int64_t>& target_epoch,
                                 const uint32_t max_diff_seconds) {
  if (records.empty()) return nullptr;

  if (!target_epoch.has_value()) {
    return &records.back();
  }

  const TRecord* best_record = nullptr;
  int64_t best_diff = std::numeric_limits<int64_t>::max();
  for (const TRecord& record : records) {
    if (!record.epoch_seconds.has_value()) continue;
    const int64_t diff =
        absoluteDifference(*record.epoch_seconds, *target_epoch);
    if (diff > static_cast<int64_t>(max_diff_seconds)) continue;
    if (diff < best_diff) {
      best_diff = diff;
      best_record = &record;
    }
  }
  return best_record;
}

std::optional<LogonSessionRecord> buildLogonSessionRecord(
    const EventLogAnalysis::IEventData& event) {
  const auto& data = event.getData();

  LogonSessionRecord record;
  record.timestamp = formatEventTimestamp(event.getTimestamp());
  record.epoch_seconds = parseTimestampToEpoch(record.timestamp);

  if (const auto* value = findDataValue(data, {"TargetLogonId", "LogonId"});
      value != nullptr) {
    record.logon_id_text = trim_copy(*value);
    record.logon_id = parseUInt64Flexible(record.logon_id_text);
  }

  record.user =
      buildUser(findDataValue(data, {"TargetDomainName", "UserDomain"}),
                findDataValue(data, {"TargetUserName", "UserName"}));

  if (const auto* sid = findDataValue(data, {"TargetUserSid", "UserSid"});
      sid != nullptr) {
    record.user_sid = trim_copy(*sid);
  }
  if (const auto* logon_type = findDataValue(data, {"LogonType"});
      logon_type != nullptr) {
    record.logon_type = normalizeLogonType(*logon_type);
  }
  if (const auto* elevated_token = findDataValue(data, {"ElevatedToken"});
      elevated_token != nullptr) {
    record.elevated_token = normalizeElevatedToken(*elevated_token);
  }

  if (record.logon_id_text.empty() && !record.logon_id.has_value()) {
    return std::nullopt;
  }
  return record;
}

std::optional<PrivilegedLogonRecord> buildPrivilegedLogonRecord(
    const EventLogAnalysis::IEventData& event) {
  const auto& data = event.getData();

  PrivilegedLogonRecord record;
  record.timestamp = formatEventTimestamp(event.getTimestamp());
  record.epoch_seconds = parseTimestampToEpoch(record.timestamp);

  if (const auto* value = findDataValue(data, {"SubjectLogonId", "LogonId"});
      value != nullptr) {
    record.logon_id_text = trim_copy(*value);
    record.logon_id = parseUInt64Flexible(record.logon_id_text);
  }

  if (const auto* privileges = findDataValue(data, {"PrivilegeList"});
      privileges != nullptr) {
    record.privileges = parsePrivileges(*privileges);
  }

  if ((record.logon_id_text.empty() && !record.logon_id.has_value()) ||
      record.privileges.empty()) {
    return std::nullopt;
  }
  return record;
}

std::optional<ProcessCreationRecord> buildProcessCreationRecord(
    const EventLogAnalysis::IEventData& event) {
  const auto& data = event.getData();

  ProcessCreationRecord record;
  record.timestamp = formatEventTimestamp(event.getTimestamp());
  record.epoch_seconds = parseTimestampToEpoch(record.timestamp);

  if (const auto* value = findDataValue(
          data, {"NewProcessName", "ProcessName", "Application", "Image"});
      value != nullptr) {
    record.process_path = normalizeProcessPath(*value);
  }

  if (const auto* command_line =
          findDataValue(data, {"CommandLine", "ProcessCommandLine"});
      command_line != nullptr) {
    record.command_line = trim_copy(*command_line);
  }

  if (const auto* pid = findDataValue(data, {"NewProcessId", "NewProcessID",
                                             "ProcessId", "ProcessID", "PID"});
      pid != nullptr) {
    if (const auto parsed_pid = parseUInt32Flexible(*pid);
        parsed_pid.has_value()) {
      record.pid = *parsed_pid;
    }
  }

  if (const auto* value =
          findDataValue(data, {"SubjectLogonId", "TargetLogonId", "LogonId"});
      value != nullptr) {
    record.logon_id_text = trim_copy(*value);
    record.logon_id = parseUInt64Flexible(record.logon_id_text);
  }

  record.user = buildUser(
      findDataValue(data,
                    {"SubjectDomainName", "TargetDomainName", "UserDomain"}),
      findDataValue(data, {"SubjectUserName", "TargetUserName", "UserName"}));

  if (const auto* sid = findDataValue(
          data, {"SubjectUserSid", "TargetUserSid", "UserSid", "SecurityID"});
      sid != nullptr) {
    record.user_sid = trim_copy(*sid);
  }

  if (const auto* elevation = findDataValue(data, {"TokenElevationType"});
      elevation != nullptr) {
    record.elevation_type = normalizeElevationType(*elevation);
  }
  if (const auto* elevated_token = findDataValue(data, {"ElevatedToken"});
      elevated_token != nullptr) {
    record.elevated_token = normalizeElevatedToken(*elevated_token);
  }
  if (const auto* mandatory_label =
          findDataValue(data, {"MandatoryLabel", "IntegrityLevel"});
      mandatory_label != nullptr) {
    record.integrity_level = normalizeIntegrityLevel(*mandatory_label);
  }

  if (record.process_path.empty() && record.command_line.empty() &&
      record.pid == 0) {
    return std::nullopt;
  }
  return record;
}

std::optional<std::string> findProcessKeyByPid(
    const std::vector<NetworkConnection>& network_connections,
    const uint32_t pid, const std::optional<int64_t>& process_epoch,
    const uint32_t correlation_window_seconds) {
  if (pid == 0) return std::nullopt;

  std::optional<std::string> best_key;
  int64_t best_diff = std::numeric_limits<int64_t>::max();

  for (const auto& connection : network_connections) {
    if (connection.process_id != pid) continue;

    std::string candidate = connection.process_name;
    if (candidate.empty()) candidate = connection.application;
    trim(candidate);
    if (candidate.empty()) continue;

    if (!process_epoch.has_value()) {
      return candidate;
    }

    const auto connection_epoch = parseTimestampToEpoch(connection.timestamp);
    if (!connection_epoch.has_value()) continue;

    const int64_t diff = absoluteDifference(*connection_epoch, *process_epoch);
    if (diff > static_cast<int64_t>(correlation_window_seconds)) continue;

    if (diff < best_diff) {
      best_diff = diff;
      best_key = candidate;
    }
  }

  return best_key;
}

/// @brief Предварительно вычисленный индекс для O(1)-поиска канонического
/// ключа. Строится один раз перед основным циклом корреляции — вместо O(n)
/// скана на каждый запрос.
struct ProcessKeyIndex {
  /// lowercase(full_path) → оригинальный ключ
  std::unordered_map<std::string, std::string> by_path;
  /// lowercase(filename) → оригинальный ключ (первое вхождение побеждает)
  std::unordered_map<std::string, std::string> by_filename;
};

ProcessKeyIndex buildProcessKeyIndex(
    const std::unordered_map<std::string, ProcessInfo>& process_data) {
  ProcessKeyIndex idx;
  idx.by_path.reserve(process_data.size());
  idx.by_filename.reserve(process_data.size());
  for (const auto& [key, _] : process_data) {
    idx.by_path.try_emplace(to_lower(key), key);
    const std::string fname = to_lower(fs::path(key).filename().string());
    if (!fname.empty()) {
      idx.by_filename.try_emplace(fname, key);
    }
  }
  return idx;
}

std::string findCanonicalProcessKey(const ProcessKeyIndex& index,
                                    const std::string& candidate_key) {
  if (candidate_key.empty()) return {};

  const std::string lowered = to_lower(candidate_key);
  if (const auto it = index.by_path.find(lowered); it != index.by_path.end()) {
    return it->second;
  }

  const std::string fname =
      to_lower(fs::path(candidate_key).filename().string());
  if (!fname.empty()) {
    if (const auto it = index.by_filename.find(fname);
        it != index.by_filename.end()) {
      return it->second;
    }
  }

  return candidate_key;
}

void appendEvidenceSource(ProcessInfo& info, const std::string& source) {
  EvidenceUtils::appendUniqueToken(info.evidence_sources, source);
}

void appendTimelineArtifact(ProcessInfo& info, const std::string& artifact) {
  EvidenceUtils::appendUniqueToken(info.timeline_artifacts, artifact);
}

void appendProcessSecurityContext(const ProcessCreationRecord& record,
                                  ProcessInfo& info) {
  if (!record.user.empty()) {
    EvidenceUtils::appendUniqueToken(info.users, record.user);
  }
  if (!record.user_sid.empty()) {
    EvidenceUtils::appendUniqueToken(info.user_sids, record.user_sid);
  }

  const std::string logon_id =
      toCanonicalLogonId(record.logon_id, record.logon_id_text);
  if (!logon_id.empty()) {
    EvidenceUtils::appendUniqueToken(info.logon_ids, logon_id);
  }

  if (!record.elevation_type.empty()) {
    info.elevation_type = record.elevation_type;
  }
  if (!record.elevated_token.empty()) {
    info.elevated_token = record.elevated_token;
  }
  if (!record.integrity_level.empty()) {
    info.integrity_level = record.integrity_level;
  }
  if (!record.command_line.empty() && info.command.empty()) {
    info.command = record.command_line;
  }

  if (EvidenceUtils::isTimestampLike(record.timestamp)) {
    EvidenceUtils::appendUniqueToken(info.run_times, record.timestamp);
    EvidenceUtils::updateTimestampMin(info.first_seen_utc, record.timestamp);
    EvidenceUtils::updateTimestampMax(info.last_seen_utc, record.timestamp);
  }

  appendEvidenceSource(info, "SecurityContext");

  std::string timeline = "[Security4688] ts=" + record.timestamp;
  if (record.pid > 0) {
    timeline += " pid=" + std::to_string(record.pid);
  }
  if (!logon_id.empty()) {
    timeline += " logon=" + logon_id;
  }
  appendTimelineArtifact(info, timeline);
}

void appendLogonSessionContext(const LogonSessionRecord& record,
                               ProcessInfo& info) {
  if (!record.user.empty()) {
    EvidenceUtils::appendUniqueToken(info.users, record.user);
  }
  if (!record.user_sid.empty()) {
    EvidenceUtils::appendUniqueToken(info.user_sids, record.user_sid);
  }

  const std::string logon_id =
      toCanonicalLogonId(record.logon_id, record.logon_id_text);
  if (!logon_id.empty()) {
    EvidenceUtils::appendUniqueToken(info.logon_ids, logon_id);
  }
  if (!record.logon_type.empty()) {
    EvidenceUtils::appendUniqueToken(info.logon_types, record.logon_type);
  }
  if (info.elevated_token.empty() && !record.elevated_token.empty()) {
    info.elevated_token = record.elevated_token;
  }

  std::string timeline = "[Security4624] ts=" + record.timestamp;
  if (!logon_id.empty()) timeline += " logon=" + logon_id;
  if (!record.logon_type.empty()) timeline += " type=" + record.logon_type;
  appendTimelineArtifact(info, timeline);
}

void appendPrivilegedContext(const PrivilegedLogonRecord& record,
                             ProcessInfo& info) {
  for (const std::string& privilege : record.privileges) {
    EvidenceUtils::appendUniqueToken(info.privileges, privilege);
  }

  const std::string logon_id =
      toCanonicalLogonId(record.logon_id, record.logon_id_text);
  std::string timeline = "[Security4672] ts=" + record.timestamp;
  if (!logon_id.empty()) timeline += " logon=" + logon_id;
  timeline += " privileges=" + std::to_string(record.privileges.size());
  appendTimelineArtifact(info, timeline);
}

}  // namespace

SecurityContextAnalyzer::SecurityContextAnalyzer(
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
    std::string os_version, const std::string& ini_path)
    : evt_parser_(std::move(evt_parser)),
      evtx_parser_(std::move(evtx_parser)),
      os_version_(std::move(os_version)) {
  trim(os_version_);
  loadConfig(ini_path);
}

void SecurityContextAnalyzer::loadConfig(const std::string& ini_path) {
  Config config(ini_path, false, false);

  if (config.hasKey(std::string(kSecurityContextSection), "Enabled")) {
    config_.enabled =
        config.getBool(std::string(kSecurityContextSection), "Enabled", true);
  }

  if (config.hasKey(std::string(kSecurityContextSection), "SecurityLogPath")) {
    config_.security_log_path =
        config.getString(std::string(kSecurityContextSection),
                         "SecurityLogPath", config_.security_log_path);
  } else if (config.hasKey(std::string(kExecutionArtifactsSection),
                           "SecurityLogPath")) {
    config_.security_log_path =
        config.getString(std::string(kExecutionArtifactsSection),
                         "SecurityLogPath", config_.security_log_path);
  }

  if (config.hasKey(std::string(kSecurityContextSection),
                    "ProcessCreateEventIDs")) {
    const auto ids = parseEventIds(config.getString(
        std::string(kSecurityContextSection), "ProcessCreateEventIDs", ""));
    if (!ids.empty()) config_.process_create_event_ids = ids;
  }

  if (config.hasKey(std::string(kSecurityContextSection), "LogonEventIDs")) {
    const auto ids = parseEventIds(config.getString(
        std::string(kSecurityContextSection), "LogonEventIDs", ""));
    if (!ids.empty()) config_.logon_event_ids = ids;
  }

  if (config.hasKey(std::string(kSecurityContextSection),
                    "PrivilegeEventIDs")) {
    const auto ids = parseEventIds(config.getString(
        std::string(kSecurityContextSection), "PrivilegeEventIDs", ""));
    if (!ids.empty()) config_.privilege_event_ids = ids;
  }

  const int logon_window = config.getInt(
      std::string(kSecurityContextSection), "LogonCorrelationWindowSeconds",
      static_cast<int>(config_.logon_correlation_window_seconds));
  if (logon_window > 0) {
    config_.logon_correlation_window_seconds =
        static_cast<uint32_t>(logon_window);
  }

  const int pid_window = config.getInt(
      std::string(kSecurityContextSection), "PidCorrelationWindowSeconds",
      static_cast<int>(config_.pid_correlation_window_seconds));
  if (pid_window > 0) {
    config_.pid_correlation_window_seconds = static_cast<uint32_t>(pid_window);
  }
}

std::string SecurityContextAnalyzer::resolveSecurityLogPath(
    const std::string& disk_root) const {
  fs::path configured_path = fs::path(config_.security_log_path);
  if (configured_path.empty()) return {};

  if (!configured_path.is_absolute()) {
    configured_path = fs::path(disk_root) / configured_path;
  }

  std::error_code ec;
  if (fs::exists(configured_path, ec) && !ec) {
    return configured_path.string();
  }

  if (configured_path.has_extension()) {
    fs::path alternative_path = configured_path;
    const std::string extension =
        to_lower(configured_path.extension().string());
    if (extension == ".evtx") {
      alternative_path.replace_extension(".evt");
    } else if (extension == ".evt") {
      alternative_path.replace_extension(".evtx");
    }
    if (alternative_path != configured_path &&
        fs::exists(alternative_path, ec) && !ec) {
      return alternative_path.string();
    }
  }

  return configured_path.string();
}

EventLogAnalysis::IEventLogParser* SecurityContextAnalyzer::getParserForFile(
    const std::string& file_path) const {
  std::string ext = fs::path(file_path).extension().string();
  std::ranges::transform(ext, ext.begin(), [](const unsigned char ch) {
    return std::tolower(ch);
  });

  if (ext == ".evt") return evt_parser_.get();
  if (ext == ".evtx") return evtx_parser_.get();
  return nullptr;
}

void SecurityContextAnalyzer::collect(
    const std::string& disk_root,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<NetworkConnection>& network_connections) {
  const auto logger = GlobalLogger::get();

  if (!config_.enabled) {
    logger->info("SecurityContext: анализ отключён");
    return;
  }

  const std::string security_log_path = resolveSecurityLogPath(disk_root);
  if (security_log_path.empty()) {
    logger->warn("SecurityContext: путь к Security log не задан");
    return;
  }

  std::error_code ec;
  if (!fs::exists(security_log_path, ec) || ec) {
    logger->warn("SecurityContext: Security log не найден");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SecurityContext: отсутствует файл \"{}\"", security_log_path);
    return;
  }

  EventLogAnalysis::IEventLogParser* parser =
      getParserForFile(security_log_path);
  if (parser == nullptr) {
    logger->warn("SecurityContext: неподдерживаемый формат Security log");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SecurityContext: расширение файла \"{}\" не поддерживается",
                security_log_path);
    return;
  }

  std::vector<std::unique_ptr<EventLogAnalysis::IEventData>> events;
  try {
    events = parser->parseEvents(security_log_path);
  } catch (const std::exception& exception) {
    logger->error("SecurityContext: ошибка разбора Security log");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SecurityContext: parseEvents(\"{}\") failed: {}",
                security_log_path, exception.what());
    return;
  }

  if (events.empty()) {
    logger->info("SecurityContext: событий не обнаружено");
    return;
  }

  const std::unordered_set<uint32_t> process_event_ids(
      config_.process_create_event_ids.begin(),
      config_.process_create_event_ids.end());
  const std::unordered_set<uint32_t> logon_event_ids(
      config_.logon_event_ids.begin(), config_.logon_event_ids.end());
  const std::unordered_set<uint32_t> privilege_event_ids(
      config_.privilege_event_ids.begin(), config_.privilege_event_ids.end());

  std::vector<ProcessCreationRecord> process_records;
  std::vector<LogonSessionRecord> logon_records;
  std::vector<PrivilegedLogonRecord> privilege_records;
  process_records.reserve(events.size() / 2);
  logon_records.reserve(events.size() / 4);
  privilege_records.reserve(events.size() / 8);

  for (const auto& event : events) {
    if (!event) continue;
    const uint32_t event_id = event->getEventID();

    if (process_event_ids.contains(event_id)) {
      if (auto record = buildProcessCreationRecord(*event);
          record.has_value()) {
        process_records.push_back(std::move(*record));
      }
      continue;
    }

    if (logon_event_ids.contains(event_id)) {
      if (auto record = buildLogonSessionRecord(*event); record.has_value()) {
        logon_records.push_back(std::move(*record));
      }
      continue;
    }

    if (privilege_event_ids.contains(event_id)) {
      if (auto record = buildPrivilegedLogonRecord(*event);
          record.has_value()) {
        privilege_records.push_back(std::move(*record));
      }
    }
  }

  std::unordered_map<uint64_t, std::vector<LogonSessionRecord>> logons_by_id;
  logons_by_id.reserve(logon_records.size());
  for (const auto& record : logon_records) {
    if (record.logon_id.has_value()) {
      logons_by_id[*record.logon_id].push_back(record);
    }
  }

  std::unordered_map<uint64_t, std::vector<PrivilegedLogonRecord>>
      privileges_by_id;
  privileges_by_id.reserve(privilege_records.size());
  for (const auto& record : privilege_records) {
    if (record.logon_id.has_value()) {
      privileges_by_id[*record.logon_id].push_back(record);
    }
  }

  auto sort_by_timestamp = [](auto& records) {
    std::ranges::sort(records, [](const auto& left, const auto& right) {
      if (left.epoch_seconds.has_value() && right.epoch_seconds.has_value()) {
        return *left.epoch_seconds < *right.epoch_seconds;
      }
      return left.timestamp < right.timestamp;
    });
  };
  for (auto& [_, records] : logons_by_id) {
    sort_by_timestamp(records);
  }
  for (auto& [_, records] : privileges_by_id) {
    sort_by_timestamp(records);
  }

  // Строим индекс один раз — O(m), после чего каждый вызов
  // findCanonicalProcessKey O(1) вместо O(m) на каждый из n process_records →
  // итого O(n+m) вместо O(n*m).
  const ProcessKeyIndex key_index = buildProcessKeyIndex(process_data);

  std::size_t correlated_processes = 0;
  std::size_t pid_resolved_processes = 0;

  for (const ProcessCreationRecord& record : process_records) {
    std::string process_key = record.process_path;
    if (process_key.empty()) {
      if (auto command_key =
              EvidenceUtils::extractExecutableFromCommand(record.command_line);
          command_key.has_value()) {
        process_key = normalizeProcessPath(*command_key);
      }
    }

    bool resolved_by_pid = false;
    if (process_key.empty()) {
      if (auto pid_key = findProcessKeyByPid(
              network_connections, record.pid, record.epoch_seconds,
              config_.pid_correlation_window_seconds);
          pid_key.has_value()) {
        process_key = normalizeProcessPath(*pid_key);
        resolved_by_pid = true;
      }
    }

    if (process_key.empty()) continue;

    process_key = findCanonicalProcessKey(key_index, process_key);
    ProcessInfo& info = process_data[process_key];
    if (info.filename.empty()) {
      info.filename = process_key;
    }

    appendProcessSecurityContext(record, info);

    bool correlated = false;
    if (record.logon_id.has_value()) {
      if (const auto it = logons_by_id.find(*record.logon_id);
          it != logons_by_id.end()) {
        if (const LogonSessionRecord* best_match =
                findNearestByTime(it->second, record.epoch_seconds,
                                  config_.logon_correlation_window_seconds);
            best_match != nullptr) {
          appendLogonSessionContext(*best_match, info);
          correlated = true;
        }
      }

      if (const auto it = privileges_by_id.find(*record.logon_id);
          it != privileges_by_id.end()) {
        if (const PrivilegedLogonRecord* best_match =
                findNearestByTime(it->second, record.epoch_seconds,
                                  config_.logon_correlation_window_seconds);
            best_match != nullptr) {
          appendPrivilegedContext(*best_match, info);
          correlated = true;
        }
      }
    }

    if (correlated) {
      correlated_processes++;
    }
    if (resolved_by_pid) {
      pid_resolved_processes++;
      appendTimelineArtifact(info,
                             "[SecurityCorrelation] process_resolved_by_pid");
    }
  }

  logger->info("SecurityContext: 4688={}, 4624={}, 4672={}, correlated={}",
               process_records.size(), logon_records.size(),
               privilege_records.size(), correlated_processes);
  if (pid_resolved_processes > 0) {
    logger->info("SecurityContext: PID-correlated processes={}",
                 pid_resolved_processes);
  }
}

}  // namespace WindowsDiskAnalysis
