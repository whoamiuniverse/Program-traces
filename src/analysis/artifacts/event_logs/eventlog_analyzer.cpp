#include "eventlog_analyzer.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <future>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "common/utils.hpp"
#include "parsers/event_log/evt/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {
namespace {

constexpr std::string_view kVersionDefaultsSection = "VersionDefaults";

std::string getConfigValueWithFallback(const Config& config,
                                       const std::string& version,
                                       const std::string& key) {
  if (config.hasKey(version, key)) {
    return config.getString(version, key, "");
  }

  if (config.hasKey(std::string(kVersionDefaultsSection), key)) {
    return config.getString(std::string(kVersionDefaultsSection), key, "");
  }

  return {};
}

std::vector<uint32_t> parseEventIds(const std::string& raw_ids,
                                    const std::string& category,
                                    const auto& logger) {
  std::vector<uint32_t> ids;
  for (auto& id_str : split(raw_ids, ',')) {
    trim(id_str);
    if (id_str.empty()) continue;

    uint32_t event_id = 0;
    if (tryParseUInt32(id_str, event_id)) {
      ids.push_back(event_id);
    } else {
      logger->debug("Некорректный {} ID события: \"{}\"", category, id_str);
    }
  }

  return ids;
}

std::string formatEventTimestamp(const uint64_t raw_timestamp) {
  constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
  constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

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

std::optional<uint16_t> parseUInt16Flexible(std::string raw_value) {
  trim(raw_value);
  if (raw_value.empty()) return std::nullopt;

  uint16_t parsed_value = 0;
  if (tryParseUInt16(raw_value, parsed_value)) {
    return parsed_value;
  }

  try {
    const unsigned long parsed_long = std::stoul(raw_value, nullptr, 0);
    if (parsed_long <= std::numeric_limits<uint16_t>::max()) {
      return static_cast<uint16_t>(parsed_long);
    }
  } catch (...) {
  }

  return std::nullopt;
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

std::string normalizeProtocol(const std::string& raw_protocol) {
  std::string protocol = trim_copy(raw_protocol);
  if (protocol.empty()) return {};

  const std::string lowered = to_lower(protocol);
  if (lowered == "6") return "TCP";
  if (lowered == "17") return "UDP";
  if (lowered == "1") return "ICMP";
  if (lowered == "58") return "ICMPv6";
  if (lowered == "tcp") return "TCP";
  if (lowered == "udp") return "UDP";
  if (lowered == "icmp") return "ICMP";
  if (lowered == "icmpv6") return "ICMPv6";
  return protocol;
}

std::string normalizeDirection(const std::string& raw_direction) {
  const std::string lowered = to_lower(trim_copy(raw_direction));
  if (lowered.empty()) return {};
  if (lowered == "%%14592" || lowered == "outbound") return "outbound";
  if (lowered == "%%14593" || lowered == "inbound") return "inbound";
  return lowered;
}

std::string normalizeAction(std::string raw_action, const uint32_t event_id) {
  trim(raw_action);
  const std::string lowered = to_lower(raw_action);
  if (lowered == "%%14500" || lowered == "allow" || lowered == "allowed") {
    return "allow";
  }
  if (lowered == "%%14501" || lowered == "block" || lowered == "blocked" ||
      lowered == "deny" || lowered == "denied") {
    return "block";
  }

  if (event_id == 5156) return "allow";
  if (event_id == 5157) return "block";
  return raw_action;
}

std::string normalizeLogonType(std::string raw_type) {
  trim(raw_type);
  if (raw_type.empty()) return {};

  const auto logon_type = parseUInt32Flexible(raw_type);
  if (!logon_type.has_value()) return raw_type;

  switch (*logon_type) {
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
      return std::to_string(*logon_type);
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

void appendPrivilegesFromString(ProcessInfo& info, std::string raw_privileges) {
  trim(raw_privileges);
  if (raw_privileges.empty() || raw_privileges == "-") return;

  for (char& ch : raw_privileges) {
    if (ch == ',' || ch == ';' || ch == '|' || ch == '\t' || ch == '\n') {
      ch = ' ';
    }
  }

  std::istringstream stream(raw_privileges);
  std::string token;
  while (stream >> token) {
    trim(token);
    if (!token.empty() && token != "-") {
      EvidenceUtils::appendUniqueToken(info.privileges, std::move(token));
    }
  }
}

void enrichProcessContextFromEvent(const std::unordered_map<std::string, std::string>& data,
                                   ProcessInfo& info) {
  const std::string user_name =
      findDataValue(data, {"SubjectUserName", "TargetUserName", "UserName"}) == nullptr
          ? ""
          : *findDataValue(data, {"SubjectUserName", "TargetUserName", "UserName"});
  const std::string user_domain =
      findDataValue(data, {"SubjectDomainName", "TargetDomainName", "UserDomain"}) ==
              nullptr
          ? ""
          : *findDataValue(data, {"SubjectDomainName", "TargetDomainName", "UserDomain"});

  if (!user_name.empty() && user_name != "-") {
    std::string normalized_user = trim_copy(user_name);
    if (!user_domain.empty() && user_domain != "-" &&
        to_lower(user_domain) != "n/a") {
      normalized_user = trim_copy(user_domain) + "\\" + normalized_user;
    }
    EvidenceUtils::appendUniqueToken(info.users, std::move(normalized_user));
  }

  if (const auto* sid = findDataValue(
          data, {"SubjectUserSid", "TargetUserSid", "UserSid", "SecurityID"});
      sid != nullptr) {
    EvidenceUtils::appendUniqueToken(info.user_sids, *sid);
  }

  if (const auto* logon_id = findDataValue(
          data, {"SubjectLogonId", "TargetLogonId", "LogonId"});
      logon_id != nullptr) {
    EvidenceUtils::appendUniqueToken(info.logon_ids, *logon_id);
  }

  if (const auto* logon_type = findDataValue(data, {"LogonType"});
      logon_type != nullptr) {
    EvidenceUtils::appendUniqueToken(info.logon_types,
                                     normalizeLogonType(*logon_type));
  }

  if (const auto* elevation = findDataValue(data, {"TokenElevationType"});
      elevation != nullptr) {
    const std::string normalized_elevation = normalizeElevationType(*elevation);
    if (!normalized_elevation.empty()) {
      info.elevation_type = normalized_elevation;
    }
  }

  if (const auto* elevated_token = findDataValue(data, {"ElevatedToken"});
      elevated_token != nullptr) {
    const std::string normalized_elevated_token =
        normalizeElevatedToken(*elevated_token);
    if (!normalized_elevated_token.empty()) {
      info.elevated_token = normalized_elevated_token;
    }
  }

  if (const auto* integrity_level =
          findDataValue(data, {"MandatoryLabel", "IntegrityLevel"});
      integrity_level != nullptr) {
    const std::string normalized_integrity = normalizeIntegrityLevel(*integrity_level);
    if (!normalized_integrity.empty()) {
      info.integrity_level = normalized_integrity;
    }
  }

  if (const auto* privileges = findDataValue(data, {"PrivilegeList"});
      privileges != nullptr) {
    appendPrivilegesFromString(info, *privileges);
  }
}

struct EventLogFileParseResult {
  std::unordered_map<std::string, ProcessInfo> process_data;
  std::vector<NetworkConnection> network_connections;
};

void mergeProcessInfo(ProcessInfo& target, const ProcessInfo& source) {
  if (target.filename.empty()) {
    target.filename = source.filename;
  }
  if (target.command.empty()) {
    target.command = source.command;
  }

  target.run_count += source.run_count;
  target.run_times.insert(target.run_times.end(), source.run_times.begin(),
                          source.run_times.end());
  target.volumes.insert(target.volumes.end(), source.volumes.begin(),
                        source.volumes.end());
  target.metrics.insert(target.metrics.end(), source.metrics.begin(),
                        source.metrics.end());

  for (const auto& user : source.users) {
    EvidenceUtils::appendUniqueToken(target.users, user);
  }
  for (const auto& sid : source.user_sids) {
    EvidenceUtils::appendUniqueToken(target.user_sids, sid);
  }
  for (const auto& logon_id : source.logon_ids) {
    EvidenceUtils::appendUniqueToken(target.logon_ids, logon_id);
  }
  for (const auto& logon_type : source.logon_types) {
    EvidenceUtils::appendUniqueToken(target.logon_types, logon_type);
  }
  for (const auto& privilege : source.privileges) {
    EvidenceUtils::appendUniqueToken(target.privileges, privilege);
  }
  for (const auto& source_name : source.evidence_sources) {
    EvidenceUtils::appendUniqueToken(target.evidence_sources, source_name);
  }
  for (const auto& flag : source.tamper_flags) {
    EvidenceUtils::appendUniqueToken(target.tamper_flags, flag);
  }
  for (const auto& timeline : source.timeline_artifacts) {
    EvidenceUtils::appendUniqueToken(target.timeline_artifacts, timeline);
  }
  for (const auto& recovered : source.recovered_from) {
    EvidenceUtils::appendUniqueToken(target.recovered_from, recovered);
  }

  if (target.elevation_type.empty()) {
    target.elevation_type = source.elevation_type;
  }
  if (target.elevated_token.empty()) {
    target.elevated_token = source.elevated_token;
  }
  if (target.integrity_level.empty()) {
    target.integrity_level = source.integrity_level;
  }

  EvidenceUtils::updateTimestampMin(target.first_seen_utc, source.first_seen_utc);
  EvidenceUtils::updateTimestampMax(target.last_seen_utc, source.last_seen_utc);
}

void mergeProcessMaps(std::unordered_map<std::string, ProcessInfo>& target,
                      const std::unordered_map<std::string, ProcessInfo>& source) {
  for (const auto& [process_name, process_info] : source) {
    auto& target_info = target[process_name];
    mergeProcessInfo(target_info, process_info);
  }
}

EventLogFileParseResult parseLogFile(
    const std::string& file_path, const EventLogConfig& cfg,
    const std::shared_ptr<spdlog::logger>& logger) {
  EventLogFileParseResult result;

  EventLogAnalysis::IEventLogParser* parser = nullptr;
  std::unique_ptr<EventLogAnalysis::EvtParser> local_evt_parser;
  std::unique_ptr<EventLogAnalysis::EvtxParser> local_evtx_parser;

  std::string extension = fs::path(file_path).extension().string();
  std::ranges::transform(extension, extension.begin(),
                         [](const unsigned char ch) {
                           return static_cast<char>(std::tolower(ch));
                         });
  if (extension == ".evt") {
    local_evt_parser = std::make_unique<EventLogAnalysis::EvtParser>();
    parser = local_evt_parser.get();
  } else if (extension == ".evtx") {
    local_evtx_parser = std::make_unique<EventLogAnalysis::EvtxParser>();
    parser = local_evtx_parser.get();
  } else {
    logger->debug("Неизвестный формат журнала: \"{}\"", file_path);
    return result;
  }

  for (const uint32_t event_id : cfg.process_event_ids) {
    try {
      for (const auto& event : parser->getEventsByType(file_path, event_id)) {
        const auto& data = event->getData();
        const auto* process_name = findDataValue(
            data, {"NewProcessName", "ProcessName", "Application", "Image"});
        if (process_name == nullptr) continue;

        std::string process_name_value = trim_copy(*process_name);
        if (process_name_value.empty()) continue;

        ProcessInfo& info = result.process_data[process_name_value];
        info.filename = process_name_value;

        if (const auto* command_line =
                findDataValue(data, {"CommandLine", "ProcessCommandLine"});
            command_line != nullptr && info.command.empty()) {
          info.command = *command_line;
        }

        info.run_times.push_back(formatEventTimestamp(event->getTimestamp()));
        info.run_count++;
        enrichProcessContextFromEvent(data, info);
      }
    } catch (const std::exception& e) {
      logger->error("Ошибка парсинга событий процессов");
      logger->debug(
          "Ошибка парсинга process events: файл=\"{}\", event_id={}, {}",
          file_path, event_id, e.what());
    }
  }

  for (const uint32_t event_id : cfg.network_event_ids) {
    try {
      for (const auto& event : parser->getEventsByType(file_path, event_id)) {
        const auto& data = event->getData();
        NetworkConnection conn;

        conn.event_id = event_id;
        conn.timestamp = formatEventTimestamp(event->getTimestamp());

        if (const auto* process_name =
                findDataValue(data, {"ProcessName", "NewProcessName",
                                     "ProcessImageName", "Image"});
            process_name != nullptr) {
          conn.process_name = *process_name;
        }

        if (const auto* application = findDataValue(
                data, {"Application", "ApplicationName", "ApplicationPath",
                       "AppPath"});
            application != nullptr) {
          conn.application = *application;
          if (conn.process_name.empty()) {
            conn.process_name = fs::path(*application).filename().string();
          }
        }

        if (conn.process_name.empty() && conn.application.empty()) {
          continue;
        }

        if (const auto* process_id = findDataValue(
                data, {"ProcessID", "ProcessId", "ExecutionProcessID", "PID"});
            process_id != nullptr) {
          if (const auto parsed_pid = parseUInt32Flexible(*process_id);
              parsed_pid.has_value()) {
            conn.process_id = *parsed_pid;
          }
        }

        if (const auto* source_ip =
                findDataValue(data, {"SourceAddress", "LocalAddress",
                                     "SourceIP", "SrcAddress"});
            source_ip != nullptr) {
          conn.source_ip = *source_ip;
        }

        if (const auto* dest_ip = findDataValue(
                data, {"DestAddress", "DestinationAddress", "RemoteAddress",
                       "DestIP", "DestinationIP"});
            dest_ip != nullptr) {
          conn.dest_ip = *dest_ip;
        }

        if (const auto* source_port =
                findDataValue(data, {"SourcePort", "LocalPort", "SrcPort"});
            source_port != nullptr) {
          if (const auto parsed_source_port = parseUInt16Flexible(*source_port);
              parsed_source_port.has_value()) {
            conn.source_port = *parsed_source_port;
          }
        }

        if (const auto* dest_port = findDataValue(
                data, {"DestPort", "DestinationPort", "RemotePort", "Port",
                       "DstPort"});
            dest_port != nullptr) {
          if (const auto parsed_dest_port = parseUInt16Flexible(*dest_port);
              parsed_dest_port.has_value()) {
            conn.dest_port = *parsed_dest_port;
          }
        }

        if (const auto* protocol = findDataValue(data, {"Protocol"});
            protocol != nullptr) {
          conn.protocol = normalizeProtocol(*protocol);
        }

        if (const auto* direction = findDataValue(data, {"Direction"});
            direction != nullptr) {
          conn.direction = normalizeDirection(*direction);
        }

        if (const auto* action = findDataValue(data, {"Action"});
            action != nullptr) {
          conn.action = normalizeAction(*action, event_id);
        } else {
          conn.action = normalizeAction("", event_id);
        }

        result.network_connections.push_back(std::move(conn));
      }
    } catch (const std::exception& e) {
      logger->error("Ошибка парсинга сетевых событий");
      logger->debug(
          "Ошибка парсинга network events: файл=\"{}\", event_id={}, {}",
          file_path, event_id, e.what());
    }
  }

  return result;
}

}  // namespace

EventLogAnalyzer::EventLogAnalyzer(
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
    std::string os_version, const std::string& ini_path)
    : evt_parser_(std::move(evt_parser)),
      evtx_parser_(std::move(evtx_parser)),
      os_version_(std::move(os_version)) {
  trim(os_version_);
  loadConfigurations(ini_path);
}

void EventLogAnalyzer::loadConfigurations(const std::string& ini_path) {
  Config config(ini_path, false, false);
  const auto logger = GlobalLogger::get();
  std::string versions_str = config.getString("General", "Versions", "");

  for (auto& version : split(versions_str, ',')) {
    trim(version);
    if (version.empty()) continue;

    EventLogConfig cfg;

    // Загрузка путей к журналам событий
    std::string log_paths =
        getConfigValueWithFallback(config, version, "EventLogs");
    for (auto& path : split(log_paths, ',')) {
      trim(path);
      if (!path.empty()) {
        cfg.log_paths.push_back(path);
      }
    }

    // Загрузка ID событий о процессах
    cfg.process_event_ids = parseEventIds(
        getConfigValueWithFallback(config, version, "ProcessEventIDs"),
        "process", logger);

    // Загрузка ID событий о сети
    cfg.network_event_ids = parseEventIds(
        getConfigValueWithFallback(config, version, "NetworkEventIDs"),
        "network", logger);

    configs_[version] = cfg;
    logger->debug("Загружена конфигурация журналов для \"{}\"", version);
  }

  loadPerformanceOptions(config);
}

void EventLogAnalyzer::loadPerformanceOptions(const Config& config) {
  const auto logger = GlobalLogger::get();
  if (!config.hasSection("Performance")) return;

  try {
    enable_parallel_eventlog_ =
        config.getBool("Performance", "EnableParallelEventLog",
                       config.getBool("Performance", "EnableParallelStages",
                                      enable_parallel_eventlog_));
  } catch (const std::exception& e) {
    logger->warn("Некорректный параметр [Performance]/EnableParallelEventLog");
    logger->debug("Ошибка чтения [Performance]/EnableParallelEventLog: {}",
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
    logger->debug("Ошибка чтения [Performance]/WorkerThreads: {}", e.what());
  }

  worker_threads_ = std::max<std::size_t>(1, worker_threads_);
}

EventLogAnalysis::IEventLogParser* EventLogAnalyzer::getParserForFile(
    const std::string& file_path) const {
  const fs::path path = file_path;
  std::string ext = path.extension().string();

  // Преобразование расширения к нижнему регистру
  std::ranges::transform(ext, ext.begin(),
                         [](const unsigned char c) { return std::tolower(c); });

  if (ext == ".evt") {
    return evt_parser_.get();
  }
  if (ext == ".evtx") {
    return evtx_parser_.get();
  }

  return nullptr;
}

void EventLogAnalyzer::collect(
    const std::string& disk_root,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<NetworkConnection>& network_connections) {
  const auto logger = GlobalLogger::get();

  if (!configs_.contains(os_version_)) {
    logger->warn("Конфигурация журналов событий не найдена");
    logger->debug("Отсутствует EventLogs-конфигурация для версии \"{}\"",
                  os_version_);
    return;
  }

  const auto& cfg = configs_[os_version_];
  std::vector<std::string> files_to_parse;
  files_to_parse.reserve(64);

  for (const auto& log_path : cfg.log_paths) {
    const std::string full_path = disk_root + log_path;
    if (!fs::exists(full_path)) {
      logger->debug("Путь не существует: \"{}\"", full_path);
      continue;
    }

    if (fs::is_directory(full_path)) {
      for (const auto& entry : fs::directory_iterator(full_path)) {
        if (entry.is_regular_file()) {
          files_to_parse.push_back(entry.path().string());
        }
      }
    } else if (fs::is_regular_file(full_path)) {
      files_to_parse.push_back(full_path);
    } else {
      logger->debug("Путь не является ни файлом, ни директорией: \"{}\"",
                    full_path);
    }
  }

  std::sort(files_to_parse.begin(), files_to_parse.end());
  files_to_parse.erase(std::unique(files_to_parse.begin(), files_to_parse.end()),
                       files_to_parse.end());
  if (files_to_parse.empty()) return;

  const bool use_parallel =
      enable_parallel_eventlog_ && worker_threads_ > 1 &&
      files_to_parse.size() > 1;
  if (use_parallel) {
    logger->debug("EventLog: параллельный режим включен (workers={})",
                  std::min<std::size_t>(worker_threads_, files_to_parse.size()));
  }
  if (!use_parallel) {
    for (const auto& file_path : files_to_parse) {
      if (!fs::exists(file_path)) {
        logger->debug("Файл был удалён: \"{}\"", file_path);
        continue;
      }
      auto parsed = parseLogFile(file_path, cfg, logger);
      mergeProcessMaps(process_data, parsed.process_data);
      network_connections.insert(
          network_connections.end(),
          std::make_move_iterator(parsed.network_connections.begin()),
          std::make_move_iterator(parsed.network_connections.end()));
    }
    return;
  }

  const std::size_t workers =
      std::min<std::size_t>(worker_threads_, files_to_parse.size());
  std::atomic<std::size_t> next_index{0};
  std::vector<std::future<EventLogFileParseResult>> futures;
  futures.reserve(workers);

  for (std::size_t worker = 0; worker < workers; ++worker) {
    futures.push_back(std::async(std::launch::async, [&]() {
      EventLogFileParseResult worker_result;
      while (true) {
        const std::size_t index = next_index.fetch_add(1);
        if (index >= files_to_parse.size()) break;
        const std::string& file_path = files_to_parse[index];
        if (!fs::exists(file_path)) continue;

        auto parsed = parseLogFile(file_path, cfg, logger);
        mergeProcessMaps(worker_result.process_data, parsed.process_data);
        worker_result.network_connections.insert(
            worker_result.network_connections.end(),
            std::make_move_iterator(parsed.network_connections.begin()),
            std::make_move_iterator(parsed.network_connections.end()));
      }
      return worker_result;
    }));
  }

  for (auto& future : futures) {
    auto worker_result = future.get();
    mergeProcessMaps(process_data, worker_result.process_data);
    network_connections.insert(
        network_connections.end(),
        std::make_move_iterator(worker_result.network_connections.begin()),
        std::make_move_iterator(worker_result.network_connections.end()));
  }
}

}
