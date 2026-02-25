#include "execution_evidence_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/enums/value_type.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
#include <libesedb.h>
#endif

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {
namespace {

using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractAsciiStrings;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::extractUtf16LeStrings;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::isTimestampLike;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;
using EvidenceUtils::updateTimestampMax;
using EvidenceUtils::updateTimestampMin;

constexpr std::string_view kDefaultKey = "Default";
constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

std::string getConfigValueWithSectionDefault(const Config& config,
                                             const std::string& section,
                                             const std::string& key) {
  if (config.hasKey(section, key)) {
    return config.getString(section, key, "");
  }
  if (config.hasKey(section, std::string(kDefaultKey))) {
    return config.getString(section, std::string(kDefaultKey), "");
  }
  return {};
}

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) return std::nullopt;

  const fs::path relative = input_path.is_absolute()
                                ? input_path.relative_path()
                                : input_path;

  for (const fs::path& component_path : relative) {
    const std::string component = component_path.string();
    if (component.empty() || component == ".") continue;
    if (component == "..") {
      current = current.parent_path();
      continue;
    }

    const fs::path direct_candidate = current / component_path;
    ec.clear();
    if (fs::exists(direct_candidate, ec) && !ec) {
      current = direct_candidate;
      continue;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec || !fs::is_directory(current, ec)) {
      return std::nullopt;
    }

    const std::string component_lower = toLowerAscii(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;
      if (toLowerAscii(entry.path().filename().string()) == component_lower) {
        current = entry.path();
        matched = true;
        break;
      }
    }

    if (ec || !matched) {
      return std::nullopt;
    }
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) {
    return current;
  }
  return std::nullopt;
}

std::string normalizePathSeparators(std::string path) {
  std::ranges::replace(path, '\\', '/');
  return path;
}

void appendEvidenceSource(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.evidence_sources, source);
}

void appendTimelineArtifact(ProcessInfo& info, std::string artifact) {
  appendUniqueToken(info.timeline_artifacts, std::move(artifact));
}

void appendTamperFlag(std::vector<std::string>& flags, std::string flag) {
  appendUniqueToken(flags, std::move(flag));
}

void addTimestamp(ProcessInfo& info, const std::string& timestamp) {
  if (!isTimestampLike(timestamp)) return;

  info.run_times.push_back(timestamp);
  updateTimestampMin(info.first_seen_utc, timestamp);
  updateTimestampMax(info.last_seen_utc, timestamp);
}

std::string makeTimelineLabel(const std::string& source,
                              const std::string& timestamp,
                              const std::string& details) {
  std::ostringstream stream;
  if (!timestamp.empty()) {
    stream << timestamp << " ";
  }
  stream << "[" << source << "]";
  if (!details.empty()) {
    stream << " " << details;
  }
  return stream.str();
}

ProcessInfo& ensureProcessInfo(std::map<std::string, ProcessInfo>& process_data,
                               const std::string& executable_path) {
  auto& info = process_data[executable_path];
  if (info.filename.empty()) {
    info.filename = executable_path;
  }
  return info;
}

void addExecutionEvidence(std::map<std::string, ProcessInfo>& process_data,
                          const std::string& executable_path,
                          const std::string& source,
                          const std::string& timestamp,
                          const std::string& details) {
  if (executable_path.empty()) return;

  auto& info = ensureProcessInfo(process_data, executable_path);
  appendEvidenceSource(info, source);
  addTimestamp(info, timestamp);
  appendTimelineArtifact(info, makeTimelineLabel(source, timestamp, details));
}

std::vector<fs::path> collectUserHivePaths(const std::string& disk_root) {
  std::vector<fs::path> hives;
  std::error_code ec;

  auto collect_from_users_root = [&](const fs::path& users_root) {
    ec.clear();
    if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
        ec) {
      return;
    }

    for (const auto& entry : fs::directory_iterator(users_root, ec)) {
      if (ec) break;
      if (!entry.is_directory()) continue;

      const fs::path ntuser = entry.path() / "NTUSER.DAT";
      ec.clear();
      if (fs::exists(ntuser, ec) && !ec && fs::is_regular_file(ntuser, ec)) {
        hives.push_back(ntuser);
      }
    }
  };

  collect_from_users_root(fs::path(disk_root) / "Users");
  collect_from_users_root(fs::path(disk_root) / "Documents and Settings");

  return hives;
}

std::string decodeRot13(std::string value) {
  for (char& ch : value) {
    if (ch >= 'a' && ch <= 'z') {
      ch = static_cast<char>('a' + (ch - 'a' + 13) % 26);
    } else if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>('A' + (ch - 'A' + 13) % 26);
    }
  }
  return value;
}

std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value) {
  if (!value) return std::nullopt;

  try {
    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
        value->getType() ==
            RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN) {
      return value->getAsDword();
    }
    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
      const uint64_t qword = value->getAsQword();
      if (qword <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<uint32_t>(qword);
      }
      return std::nullopt;
    }
  } catch (...) {
  }

  std::string raw = value->getDataAsString();
  trim(raw);
  uint32_t parsed = 0;
  if (tryParseUInt32(raw, parsed)) {
    return parsed;
  }
  return std::nullopt;
}

std::string resolveControlSetRoot(RegistryAnalysis::IRegistryParser& parser,
                                  const std::string& system_hive_path,
                                  const std::string& current_control_set_path) {
  try {
    parser.listSubkeys(system_hive_path, current_control_set_path);
    return current_control_set_path;
  } catch (...) {
  }

  try {
    const auto current_value =
        parser.getSpecificValue(system_hive_path, "Select/Current");
    const auto index = parseControlSetIndex(current_value);
    if (!index.has_value()) return {};

    std::ostringstream stream;
    stream << "ControlSet" << std::setw(3) << std::setfill('0') << *index;
    return stream.str();
  } catch (...) {
    return {};
  }
}

std::string findPathForOsVersion(const Config& config, const std::string& section,
                                 const std::string& os_version) {
  std::string value = getConfigValueWithSectionDefault(config, section, os_version);
  if (value.empty()) {
    value = getConfigValueWithSectionDefault(config, section, std::string(kDefaultKey));
  }
  return normalizePathSeparators(std::move(value));
}

std::size_t toByteLimit(const std::size_t mb) {
  constexpr std::size_t kMegabyte = 1024 * 1024;
  if (mb == 0) return kMegabyte;
  return mb * kMegabyte;
}

void collectFileCandidates(const fs::path& file_path, const std::size_t max_bytes,
                           const std::size_t max_candidates,
                           std::vector<std::string>& output) {
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value()) return;

  const auto candidates =
      extractExecutableCandidatesFromBinary(*data_opt, max_candidates);
  output.insert(output.end(), candidates.begin(), candidates.end());
}

std::string extractUsernameFromHivePath(const fs::path& hive_path) {
  const fs::path parent = hive_path.parent_path();
  const std::string name = parent.filename().string();
  return name.empty() ? "unknown" : name;
}

std::vector<std::string> parseListSetting(std::string raw) {
  trim(raw);
  if (raw.empty()) return {};

  std::vector<std::string> values = split(raw, ',');
  for (std::string& value : values) {
    trim(value);
  }

  values.erase(std::remove_if(values.begin(), values.end(),
                              [](const std::string& value) {
                                return value.empty();
                              }),
               values.end());
  return values;
}

bool containsIgnoreCase(std::string value, const std::string& pattern) {
  value = toLowerAscii(std::move(value));
  return value.find(toLowerAscii(pattern)) != std::string::npos;
}

bool looksLikeSid(std::string value) {
  trim(value);
  if (value.size() < 6) return false;
  if (value.rfind("S-", 0) != 0 && value.rfind("s-", 0) != 0) return false;

  bool has_digit = false;
  for (char ch : value) {
    if (std::isdigit(static_cast<unsigned char>(ch)) != 0) {
      has_digit = true;
      continue;
    }
    if (ch == '-' || ch == 'S' || ch == 's') continue;
    return false;
  }
  return has_digit;
}

std::string formatReasonableFiletime(const uint64_t filetime) {
  if (filetime < kFiletimeUnixEpoch || filetime > kMaxReasonableFiletime) {
    return {};
  }
  return filetimeToString(filetime);
}

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
std::string toLibesedbErrorMessage(libesedb_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libesedb";

  std::array<char, 2048> buffer{};
  if (libesedb_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libesedb";
}

std::string sanitizeUtf8Value(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
  trim(value);
  return value;
}

std::optional<std::string> readRecordColumnNameUtf8(libesedb_record_t* record,
                                                    const int value_entry) {
  size_t name_size = 0;
  if (libesedb_record_get_utf8_column_name_size(record, value_entry, &name_size,
                                                nullptr) != 1 ||
      name_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_record_get_utf8_column_name(record, value_entry, buffer.data(),
                                           name_size, nullptr) != 1) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) return std::nullopt;
  return value;
}

std::optional<std::string> readRecordValueUtf8(libesedb_record_t* record,
                                               const int value_entry) {
  size_t utf8_size = 0;
  const int size_result = libesedb_record_get_value_utf8_string_size(
      record, value_entry, &utf8_size, nullptr);
  if (size_result <= 0 || utf8_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(utf8_size);
  if (libesedb_record_get_value_utf8_string(record, value_entry, buffer.data(),
                                            utf8_size, nullptr) <= 0) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) return std::nullopt;
  return value;
}

std::optional<std::vector<uint8_t>> readRecordValueBinary(
    libesedb_record_t* record, const int value_entry) {
  size_t binary_size = 0;
  const int size_result = libesedb_record_get_value_binary_data_size(
      record, value_entry, &binary_size, nullptr);
  if (size_result <= 0 || binary_size == 0) return std::nullopt;

  std::vector<uint8_t> data(binary_size);
  if (libesedb_record_get_value_binary_data(record, value_entry, data.data(),
                                            binary_size, nullptr) <= 0) {
    return std::nullopt;
  }
  return data;
}

std::optional<uint64_t> readRecordValueU64(libesedb_record_t* record,
                                           const int value_entry) {
  uint64_t value = 0;
  if (libesedb_record_get_value_64bit(record, value_entry, &value, nullptr) == 1) {
    return value;
  }

  uint32_t value32 = 0;
  if (libesedb_record_get_value_32bit(record, value_entry, &value32, nullptr) == 1) {
    return static_cast<uint64_t>(value32);
  }
  return std::nullopt;
}

std::optional<std::string> readRecordValueFiletimeString(libesedb_record_t* record,
                                                         const int value_entry) {
  uint64_t filetime = 0;
  if (libesedb_record_get_value_filetime(record, value_entry, &filetime,
                                         nullptr) != 1) {
    return std::nullopt;
  }
  const std::string timestamp = formatReasonableFiletime(filetime);
  if (timestamp.empty()) return std::nullopt;
  return timestamp;
}

std::string getTableNameUtf8(libesedb_table_t* table) {
  size_t name_size = 0;
  if (libesedb_table_get_utf8_name_size(table, &name_size, nullptr) != 1 ||
      name_size == 0) {
    return {};
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_table_get_utf8_name(table, buffer.data(), name_size, nullptr) != 1) {
    return {};
  }

  std::string name(reinterpret_cast<char*>(buffer.data()));
  return sanitizeUtf8Value(std::move(name));
}
#endif  // defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB

}  // namespace

ExecutionEvidenceAnalyzer::ExecutionEvidenceAnalyzer(
    std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
    std::string os_version, std::string ini_path)
    : parser_(std::move(parser)),
      os_version_(std::move(os_version)),
      ini_path_(std::move(ini_path)) {
  trim(os_version_);
  loadConfiguration();
}

void ExecutionEvidenceAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(ini_path_, false, false);

    if (!config.hasSection("ExecutionArtifacts")) {
      logger->debug("Секция [ExecutionArtifacts] не найдена, используются "
                    "значения по умолчанию");
      return;
    }

    auto readBool = [&](const std::string& key, const bool default_value) {
      try {
        return config.getBool("ExecutionArtifacts", key, default_value);
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [ExecutionArtifacts]/{}", key);
        logger->debug("Ошибка чтения [ExecutionArtifacts]/{}: {}", key, e.what());
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
    config_.enable_bam_dam = readBool("EnableBamDam", config_.enable_bam_dam);
    config_.enable_jump_lists =
        readBool("EnableJumpLists", config_.enable_jump_lists);
    config_.enable_lnk_recent =
        readBool("EnableLnkRecent", config_.enable_lnk_recent);
    config_.enable_srum = readBool("EnableSRUM", config_.enable_srum);
    config_.enable_srum_native_parser =
        readBool("EnableNativeSRUM", config_.enable_srum_native_parser);
    config_.srum_fallback_to_binary_on_native_failure = readBool(
        "SrumFallbackToBinaryOnNativeFailure",
        config_.srum_fallback_to_binary_on_native_failure);
    config_.enable_security_log_tamper_check = readBool(
        "EnableSecurityLogTamperCheck", config_.enable_security_log_tamper_check);

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
    config_.recent_lnk_suffix =
        readString("RecentLnkPath", config_.recent_lnk_suffix);
    config_.jump_auto_suffix = readString("JumpListAutoPath", config_.jump_auto_suffix);
    config_.jump_custom_suffix =
        readString("JumpListCustomPath", config_.jump_custom_suffix);
    config_.srum_path = readString("SRUMPath", config_.srum_path);
    config_.security_log_path =
        readString("SecurityLogPath", config_.security_log_path);
    config_.srum_table_allowlist =
        readList("SrumTableAllowlist", config_.srum_table_allowlist);
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить [ExecutionArtifacts]");
    logger->debug("Ошибка чтения конфигурации ExecutionArtifacts: {}", e.what());
  }
}

std::string ExecutionEvidenceAnalyzer::resolveSoftwareHivePath(
    const std::string& disk_root) const {
  Config config(ini_path_, false, false);
  const std::string relative_path =
      findPathForOsVersion(config, "OSInfoRegistryPaths", os_version_);
  if (relative_path.empty()) return {};

  const fs::path full = fs::path(disk_root) / relative_path;
  if (const auto resolved = findPathCaseInsensitive(full); resolved.has_value()) {
    return resolved->string();
  }
  return full.string();
}

std::string ExecutionEvidenceAnalyzer::resolveSystemHivePath(
    const std::string& disk_root) const {
  Config config(ini_path_, false, false);
  const std::string relative_path =
      findPathForOsVersion(config, "OSInfoSystemRegistryPaths", os_version_);
  if (relative_path.empty()) return {};

  const fs::path full = fs::path(disk_root) / relative_path;
  if (const auto resolved = findPathCaseInsensitive(full); resolved.has_value()) {
    return resolved->string();
  }
  return full.string();
}

void ExecutionEvidenceAnalyzer::collect(
    const std::string& disk_root, std::map<std::string, ProcessInfo>& process_data,
    std::vector<std::string>& global_tamper_flags) {
  const auto logger = GlobalLogger::get();
  logger->info("Запуск расширенного анализа источников исполнения");

  const std::string system_hive_path = resolveSystemHivePath(disk_root);
  if (config_.enable_shimcache && !system_hive_path.empty()) {
    collectShimCache(system_hive_path, process_data);
  }
  if (config_.enable_bam_dam && !system_hive_path.empty()) {
    collectBamDam(system_hive_path, process_data);
  }

  if (config_.enable_userassist || config_.enable_runmru) {
    collectUserAssistAndRunMru(disk_root, process_data);
  }
  if (config_.enable_lnk_recent) {
    collectLnkRecent(disk_root, process_data);
  }
  if (config_.enable_jump_lists) {
    collectJumpLists(disk_root, process_data);
  }
  if (config_.enable_srum) {
    collectSrum(disk_root, process_data);
  }
  if (config_.enable_security_log_tamper_check) {
    detectSecurityLogTampering(disk_root, global_tamper_flags);
  }
}

void ExecutionEvidenceAnalyzer::collectShimCache(
    const std::string& system_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  try {
    const auto value =
        parser_->getSpecificValue(system_hive_path, config_.shimcache_value_path);
    if (!value) return;

    std::vector<std::string> candidates;
    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
      candidates = extractExecutableCandidatesFromBinary(
          value->getAsBinary(), config_.max_candidates_per_source);
    } else {
      candidates = EvidenceUtils::extractExecutableCandidatesFromStrings(
          {value->getDataAsString()}, config_.max_candidates_per_source);
    }

    for (const auto& path : candidates) {
      addExecutionEvidence(process_data, path, "ShimCache", "",
                          "AppCompatCache");
    }
    logger->info("ShimCache: добавлено {} кандидат(ов)", candidates.size());
  } catch (const std::exception& e) {
    logger->debug("Ошибка ShimCache: {}", e.what());
  }
}

void ExecutionEvidenceAnalyzer::collectBamDam(
    const std::string& system_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  auto collect_root = [&](const std::string& root_path, const std::string& source) {
    const std::string control_set_root =
        resolveControlSetRoot(*parser_, system_hive_path, "CurrentControlSet");
    if (control_set_root.empty()) return;

    std::string normalized_root = root_path;
    const std::string marker = "CurrentControlSet/";
    if (normalized_root.rfind(marker, 0) == 0) {
      normalized_root.replace(0, marker.size(), control_set_root + "/");
    }

    std::vector<std::string> sid_subkeys;
    try {
      sid_subkeys = parser_->listSubkeys(system_hive_path, normalized_root);
    } catch (const std::exception&) {
      return;
    }

    std::size_t collected = 0;
    for (const std::string& sid : sid_subkeys) {
      const std::string sid_key = normalized_root + "/" + sid;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(system_hive_path, sid_key);
      } catch (...) {
        continue;
      }

      for (const auto& value : values) {
        std::string executable =
            getLastPathComponent(value->getName(), '/');
        if (auto parsed = extractExecutableFromCommand(executable);
            parsed.has_value()) {
          executable = *parsed;
        } else {
          continue;
        }

        std::string timestamp;
        try {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
            const auto& binary = value->getAsBinary();
            const uint64_t filetime = readLeUInt64(binary, 0);
            if (filetime >= kFiletimeUnixEpoch && filetime <= kMaxReasonableFiletime) {
              timestamp = filetimeToString(filetime);
            }
          }
        } catch (...) {
        }

        addExecutionEvidence(process_data, executable, source, timestamp,
                            source + " SID=" + sid);
        collected++;
      }
    }
    logger->info("{}: добавлено {} кандидат(ов)", source, collected);
  };

  collect_root(config_.bam_root_path, "BAM");
  collect_root(config_.dam_root_path, "DAM");
}

void ExecutionEvidenceAnalyzer::collectUserAssistAndRunMru(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(disk_root);
  if (user_hives.empty()) return;

  std::size_t userassist_count = 0;
  std::size_t runmru_count = 0;

  for (const fs::path& hive_path : user_hives) {
    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    if (config_.enable_userassist) {
      try {
        const auto guid_subkeys = parser_->listSubkeys(hive, config_.userassist_key);
        for (const std::string& guid : guid_subkeys) {
          const std::string count_key =
              config_.userassist_key + "/" + guid + "/Count";
          std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
          try {
            values = parser_->getKeyValues(hive, count_key);
          } catch (...) {
            continue;
          }

          for (const auto& value : values) {
            std::string encoded_name = getLastPathComponent(value->getName(), '/');
            if (encoded_name.empty()) continue;

            std::string decoded_name = decodeRot13(encoded_name);
            decoded_name =
                replace_all(decoded_name, "UEME_RUNPATH:", "");
            decoded_name = replace_all(decoded_name, "UEME_RUNPIDL:", "");
            trim(decoded_name);

            auto executable = extractExecutableFromCommand(decoded_name);
            if (!executable.has_value()) continue;

            uint32_t run_count = 0;
            std::string timestamp;
            if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
              const auto& binary = value->getAsBinary();
              if (binary.size() >= 8) {
                run_count = readLeUInt32(binary, 4);
              }
              if (binary.size() >= 68) {
                const uint64_t filetime = readLeUInt64(binary, 60);
                if (filetime >= kFiletimeUnixEpoch &&
                    filetime <= kMaxReasonableFiletime) {
                  timestamp = filetimeToString(filetime);
                }
              }
            }

            addExecutionEvidence(
                process_data, *executable, "UserAssist", timestamp,
                "user=" + username + ", run_count=" + std::to_string(run_count));
            userassist_count++;
          }
        }
      } catch (const std::exception& e) {
        logger->debug("UserAssist пропущен для {}: {}", hive, e.what());
      }
    }

    if (config_.enable_runmru) {
      try {
        auto values = parser_->getKeyValues(hive, config_.runmru_key);
        for (const auto& value : values) {
          std::string value_name = getLastPathComponent(value->getName(), '/');
          if (value_name.empty()) continue;
          if (toLowerAscii(value_name) == "mrulist" ||
              toLowerAscii(value_name) == "mrulistex") {
            continue;
          }

          const std::string command = value->getDataAsString();
          auto executable = extractExecutableFromCommand(command);
          if (!executable.has_value()) continue;

          addExecutionEvidence(process_data, *executable, "RunMRU", "",
                              "user=" + username + ", value=" + value_name);
          runmru_count++;
        }
      } catch (const std::exception& e) {
        logger->debug("RunMRU пропущен для {}: {}", hive, e.what());
      }
    }
  }

  logger->info("UserAssist: добавлено {} кандидат(ов)", userassist_count);
  logger->info("RunMRU: добавлено {} кандидат(ов)", runmru_count);
}

void ExecutionEvidenceAnalyzer::collectLnkRecent(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path users_root = fs::path(disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;

    const fs::path recent_dir = user_entry.path() / config_.recent_lnk_suffix;
    ec.clear();
    if (!fs::exists(recent_dir, ec) || ec || !fs::is_directory(recent_dir, ec) ||
        ec) {
      continue;
    }

    for (const auto& file_entry : fs::directory_iterator(recent_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;
      if (toLowerAscii(file_entry.path().extension().string()) != ".lnk") continue;

      std::vector<std::string> candidates;
      collectFileCandidates(file_entry.path(), max_bytes,
                            config_.max_candidates_per_source, candidates);
      if (candidates.empty()) {
        if (auto fallback = extractExecutableFromCommand(
                file_entry.path().filename().string());
            fallback.has_value()) {
          candidates.push_back(*fallback);
        }
      }

      const std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      const std::string details = "lnk=" + file_entry.path().filename().string();

      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "LNKRecent", timestamp,
                            details);
        collected++;
      }
    }
  }

  logger->info("LNK Recent: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectJumpLists(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  auto process_jump_dir = [&](const fs::path& jump_dir) {
    ec.clear();
    if (!fs::exists(jump_dir, ec) || ec || !fs::is_directory(jump_dir, ec) || ec) {
      return;
    }

    for (const auto& file_entry : fs::directory_iterator(jump_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;

      const std::string ext = toLowerAscii(file_entry.path().extension().string());
      if (ext != ".automaticdestinations-ms" && ext != ".customdestinations-ms") {
        continue;
      }

      std::vector<std::string> candidates;
      collectFileCandidates(file_entry.path(), max_bytes,
                            config_.max_candidates_per_source, candidates);

      const std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      const std::string details = "jump=" + file_entry.path().filename().string();
      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "JumpList", timestamp,
                            details);
        collected++;
      }
    }
  };

  const fs::path users_root = fs::path(disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;
    process_jump_dir(user_entry.path() / config_.jump_auto_suffix);
    process_jump_dir(user_entry.path() / config_.jump_custom_suffix);
  }

  logger->info("Jump Lists: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectSrum(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const fs::path srum_path = fs::path(disk_root) / config_.srum_path;
  const auto resolved = findPathCaseInsensitive(srum_path);
  if (!resolved.has_value()) return;

  std::size_t collected = 0;
  bool native_attempted = false;

  if (config_.enable_srum_native_parser) {
    native_attempted = true;
    collected = collectSrumNative(*resolved, process_data);
    if (collected > 0) {
      logger->info("SRUM(native): добавлено {} кандидат(ов)", collected);
      return;
    }
  }

  if (!config_.srum_fallback_to_binary_on_native_failure &&
      native_attempted) {
    logger->debug(
        "SRUM fallback отключен, бинарный режим не используется после "
        "неуспеха native-парсера");
    return;
  }

  collected = collectSrumBinaryFallback(*resolved, process_data);
  logger->info("SRUM(binary): добавлено {} кандидат(ов)", collected);
}

std::size_t ExecutionEvidenceAnalyzer::collectSrumBinaryFallback(
    const fs::path& srum_path,
    std::map<std::string, ProcessInfo>& process_data) const {
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  const auto data = readFilePrefix(srum_path, max_bytes);
  if (!data.has_value()) return 0;

  const std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
      *data, config_.max_candidates_per_source);
  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(srum_path, ec));

  for (const auto& executable : candidates) {
    addExecutionEvidence(process_data, executable, "SRUM", timestamp,
                        "sru=SRUDB.dat (binary)");
  }
  return candidates.size();
}

std::size_t ExecutionEvidenceAnalyzer::collectSrumNative(
    const fs::path& srum_path,
    std::map<std::string, ProcessInfo>& process_data) {
#if !defined(PROGRAM_TRACES_HAVE_LIBESEDB) || !PROGRAM_TRACES_HAVE_LIBESEDB
  static_cast<void>(srum_path);
  static_cast<void>(process_data);
  return 0;
#else
  const auto logger = GlobalLogger::get();

  const std::string path_string = srum_path.string();
  if (path_string.empty()) return 0;

  std::unordered_set<std::string> table_allowlist_lower;
  for (std::string table_name : config_.srum_table_allowlist) {
    trim(table_name);
    if (!table_name.empty()) {
      table_allowlist_lower.insert(toLowerAscii(std::move(table_name)));
    }
  }

  auto is_table_allowed = [&](const std::string& table_name) {
    if (table_allowlist_lower.empty()) return true;
    return table_allowlist_lower.contains(toLowerAscii(table_name));
  };

  libesedb_file_t* file = nullptr;
  libesedb_error_t* error = nullptr;

  auto free_error = [&]() {
    if (error != nullptr) {
      libesedb_error_free(&error);
      error = nullptr;
    }
  };
  auto close_file = [&]() {
    if (file != nullptr) {
      libesedb_file_close(file, nullptr);
      libesedb_file_free(&file, nullptr);
      file = nullptr;
    }
  };

  if (libesedb_file_initialize(&file, &error) != 1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug("SRUM(native): не удалось инициализировать libesedb: {}",
                  details);
    return 0;
  }

  if (libesedb_file_open(file, path_string.c_str(), LIBESEDB_OPEN_READ, &error) !=
      1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->warn("SRUM(native): не удалось открыть \"{}\" ({})", path_string,
                 details);
    return 0;
  }

  int number_of_tables = 0;
  if (libesedb_file_get_number_of_tables(file, &number_of_tables, &error) != 1 ||
      number_of_tables <= 0) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug("SRUM(native): не удалось получить список таблиц: {}",
                  details);
    return 0;
  }
  free_error();

  std::unordered_map<uint64_t, std::string> id_map;

  auto parse_id_map_table = [&](libesedb_table_t* table) {
    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      return;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        config_.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::optional<uint64_t> id_index;
      std::vector<std::string> values;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (!id_index.has_value() &&
              (column_lower == "idindex" || column_lower == "id_index" ||
               column_lower == "id")) {
            id_index = readRecordValueU64(record, value_entry);
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            values.push_back(*text);
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            auto ascii_strings = extractAsciiStrings(*binary, 6);
            auto utf16_strings = extractUtf16LeStrings(*binary, 6);
            values.insert(values.end(), ascii_strings.begin(), ascii_strings.end());
            values.insert(values.end(), utf16_strings.begin(), utf16_strings.end());
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (!id_index.has_value()) continue;

      std::string best_value;
      for (std::string value : values) {
        value = sanitizeUtf8Value(std::move(value));
        if (value.empty()) continue;
        if (looksLikeSid(value)) {
          best_value = value;
          break;
        }
        if (auto executable = extractExecutableFromCommand(value);
            executable.has_value()) {
          best_value = *executable;
          break;
        }
      }

      if (!best_value.empty()) {
        id_map[*id_index] = best_value;
      }
    }
  };

  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      parse_id_map_table(table);
    }

    libesedb_table_free(&table, nullptr);
  }

  std::size_t collected = 0;
  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    if (collected >= config_.max_candidates_per_source) break;

    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);

    if (!is_table_allowed(table_name)) {
      libesedb_table_free(&table, nullptr);
      continue;
    }
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        config_.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      if (collected >= config_.max_candidates_per_source) break;

      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::string row_timestamp;
      std::string row_sid;
      std::vector<std::string> row_executables;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (auto filetime_value =
                  readRecordValueFiletimeString(record, value_entry);
              filetime_value.has_value() &&
              (row_timestamp.empty() ||
               containsIgnoreCase(column_name, "time") ||
               containsIgnoreCase(column_name, "date") ||
               containsIgnoreCase(column_name, "stamp"))) {
            row_timestamp = *filetime_value;
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            std::string value = *text;
            if (row_sid.empty() && looksLikeSid(value) &&
                (containsIgnoreCase(column_name, "sid") ||
                 containsIgnoreCase(column_name, "user"))) {
              row_sid = value;
            }

            if (auto executable = extractExecutableFromCommand(value);
                executable.has_value()) {
              appendUniqueToken(row_executables, *executable);
            }
          }

          if (auto numeric_value = readRecordValueU64(record, value_entry);
              numeric_value.has_value()) {
            if (const auto it = id_map.find(*numeric_value); it != id_map.end()) {
              if (row_sid.empty() && looksLikeSid(it->second)) {
                row_sid = it->second;
              }
              if (auto executable = extractExecutableFromCommand(it->second);
                  executable.has_value()) {
                appendUniqueToken(row_executables, *executable);
              }
            }
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            const auto binary_candidates = extractExecutableCandidatesFromBinary(
                *binary, config_.max_candidates_per_source);
            for (const auto& executable : binary_candidates) {
              appendUniqueToken(row_executables, executable);
            }

            if (row_sid.empty()) {
              auto ascii_strings = extractAsciiStrings(*binary, 6);
              auto utf16_strings = extractUtf16LeStrings(*binary, 6);
              ascii_strings.insert(ascii_strings.end(), utf16_strings.begin(),
                                   utf16_strings.end());
              for (std::string candidate : ascii_strings) {
                candidate = sanitizeUtf8Value(std::move(candidate));
                if (looksLikeSid(candidate)) {
                  row_sid = candidate;
                  break;
                }
              }
            }
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (row_executables.empty()) continue;
      for (const auto& executable : row_executables) {
        if (collected >= config_.max_candidates_per_source) break;

        std::string details = "table=" + table_name;
        if (!row_sid.empty()) {
          details += ", sid=" + row_sid;
        }
        addExecutionEvidence(process_data, executable, "SRUM", row_timestamp,
                            details);
        collected++;
      }
    }

    libesedb_table_free(&table, nullptr);
  }

  close_file();
  return collected;
#endif
}

void ExecutionEvidenceAnalyzer::detectSecurityLogTampering(
    const std::string& disk_root, std::vector<std::string>& global_tamper_flags) {
  const auto logger = GlobalLogger::get();

  const fs::path security_log = fs::path(disk_root) / config_.security_log_path;
  const auto resolved = findPathCaseInsensitive(security_log);
  if (!resolved.has_value()) return;

  try {
    EventLogAnalysis::EvtxParser parser;
    auto events = parser.getEventsByType(resolved->string(), 1102);
    if (!events.empty()) {
      appendTamperFlag(global_tamper_flags, "security_log_cleared");
      logger->warn("Обнаружены события очистки журнала Security (ID 1102)");
    }
  } catch (const std::exception& e) {
    logger->debug("Проверка security_log_cleared пропущена: {}", e.what());
  }
}

}  // namespace WindowsDiskAnalysis
