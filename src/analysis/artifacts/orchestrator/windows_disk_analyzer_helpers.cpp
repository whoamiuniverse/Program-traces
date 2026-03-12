/// @file windows_disk_analyzer_helpers.cpp
/// @brief Реализация вспомогательных функций оркестратора WindowsDiskAnalyzer.

#include "windows_disk_analyzer_helpers.hpp"

#include <algorithm>
#include <unordered_map>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <exception>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

#ifdef __APPLE__
#include <sys/mount.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <mntent.h>
#include <unistd.h>
#endif

namespace WindowsDiskAnalysis::Orchestrator::Detail {

namespace fs = std::filesystem;

constexpr std::string_view kDefaultKey = "Default";

std::string ensureTrailingSlash(std::string path) {
  if (!path.empty() && path.back() != '/' && path.back() != '\\') {
    path.push_back('/');
  }
  return path;
}

std::string toLowerAscii(std::string text) {
  return to_lower(std::move(text));
}

void appendUniqueToken(std::vector<std::string>& target, std::string token) {
  trim(token);
  if (token.empty()) return;

  const std::string lowered = toLowerAscii(token);
  const bool already_exists = std::ranges::any_of(
      target, [&](const std::string& current) {
        return toLowerAscii(current) == lowered;
      });
  if (!already_exists) {
    target.push_back(std::move(token));
  }
}

void appendTamperFlag(ProcessInfo& info, const std::string& flag) {
  appendUniqueToken(info.tamper_flags, flag);
}

void appendEvidenceSource(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.evidence_sources, source);
}

void appendTimelineArtifact(ProcessInfo& info, const std::string& artifact) {
  appendUniqueToken(info.timeline_artifacts, artifact);
}

void appendRecoveredFrom(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.recovered_from, source);
}

bool isAutoDiskRootValue(std::string value) {
  trim(value);
  const std::string lowered = toLowerAscii(std::move(value));
  return lowered.empty() || lowered == "auto";
}

bool isAccessDeniedError(const std::error_code& ec) {
  return ec == std::errc::permission_denied ||
         ec == std::errc::operation_not_permitted;
}

bool containsAccessDenied(std::string_view message) {
  std::string lowered(message);
  lowered = toLowerAscii(std::move(lowered));
  return lowered.find("доступ запрещен") != std::string::npos ||
         lowered.find("доступ запрещён") != std::string::npos ||
         lowered.find("permission denied") != std::string::npos ||
         lowered.find("operation not permitted") != std::string::npos;
}

std::string formatFilesystemError(const std::error_code& ec) {
  if (!ec) return {};
  if (isAccessDeniedError(ec)) {
    return "доступ запрещен (" + ec.message() + ')';
  }
  return ec.message();
}

std::string formatDeviceLabel(const std::string& device_path) {
  if (device_path.empty()) return "unknown";
  const fs::path device(device_path);
  const std::string filename = device.filename().string();
  return filename.empty() ? device_path : filename;
}

bool isServerLikeValue(const std::string& value) {
  const std::string lowered = toLowerAscii(value);
  return lowered.find("server") != std::string::npos;
}

std::string normalizePathSeparators(std::string path) {
  return PathUtils::normalizePathSeparators(std::move(path));
}

std::string deriveSystemHivePathFromSoftwarePath(std::string software_hive_path) {
  software_hive_path = normalizePathSeparators(std::move(software_hive_path));
  if (software_hive_path.empty()) return {};

  fs::path hive_path(software_hive_path);
  const std::string filename = toLowerAscii(hive_path.filename().string());
  if (filename == "system") {
    return hive_path.generic_string();
  }
  if (filename != "software") {
    return {};
  }

  hive_path.replace_filename("SYSTEM");
  return hive_path.generic_string();
}

std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value) {
  if (!value) return std::nullopt;

  try {
    switch (value->getType()) {
      case RegistryAnalysis::RegistryValueType::REG_DWORD:
      case RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN:
        return value->getAsDword();
      case RegistryAnalysis::RegistryValueType::REG_QWORD: {
        const uint64_t qword = value->getAsQword();
        if (qword <= std::numeric_limits<uint32_t>::max()) {
          return static_cast<uint32_t>(qword);
        }
        return std::nullopt;
      }
      default:
        break;
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

std::string tryReadSystemProductType(RegistryAnalysis::IRegistryParser& parser,
                                     const std::string& system_hive_path) {
  auto read_product_type = [&](const std::string& value_path) -> std::string {
    const auto value = parser.getSpecificValue(system_hive_path, value_path);
    if (!value) return {};
    std::string product_type = value->getDataAsString();
    trim(product_type);
    return product_type;
  };

  try {
    std::string product_type =
        read_product_type("CurrentControlSet/Control/ProductOptions/ProductType");
    if (!product_type.empty()) {
      return product_type;
    }

    const auto current_control_set =
        parseControlSetIndex(parser.getSpecificValue(system_hive_path,
                                                     "Select/Current"));
    if (!current_control_set.has_value()) {
      return {};
    }

    std::ostringstream control_set_path;
    control_set_path << "ControlSet" << std::setw(3) << std::setfill('0')
                     << *current_control_set
                     << "/Control/ProductOptions/ProductType";
    return read_product_type(control_set_path.str());
  } catch (...) {
    return {};
  }
}

std::optional<bool> classifyServerByProductType(
    const std::string& system_product_type) {
  if (system_product_type.empty()) return std::nullopt;

  const std::string lowered = toLowerAscii(system_product_type);
  if (lowered == "servernt" || lowered == "lanmannt") return true;
  if (lowered == "winnt") return false;
  return std::nullopt;
}

std::optional<std::string> findMappedNameByBuildThreshold(
    const Config& config, const std::string& section, uint32_t build_number) {
  if (!config.hasSection(section)) return std::nullopt;

  uint32_t best_build = 0;
  std::string best_name;
  bool found = false;

  for (const auto& key : config.getKeysInSection(section)) {
    uint32_t mapped_build = 0;
    if (!tryParseUInt32(key, mapped_build)) continue;
    if (mapped_build > build_number) continue;

    const std::string mapped_name = config.getString(section, key, "");
    if (mapped_name.empty()) continue;

    if (!found || mapped_build > best_build) {
      best_build = mapped_build;
      best_name = mapped_name;
      found = true;
    }
  }

  if (!found) return std::nullopt;
  return best_name;
}

std::string resolveMappedWindowsName(const Config& config,
                                     const WindowsRootSummary& summary) {
  uint32_t build_number = 0;
  if (!tryParseUInt32(summary.build, build_number)) {
    return summary.product_name;
  }

  const auto mapped_client =
      findMappedNameByBuildThreshold(config, "BuildMappingsClient",
                                     build_number);
  const auto mapped_server =
      findMappedNameByBuildThreshold(config, "BuildMappingsServer",
                                     build_number);

  const std::optional<bool> server_by_product_type =
      classifyServerByProductType(summary.system_product_type);
  const bool prefer_server =
      server_by_product_type.has_value()
          ? *server_by_product_type
          : (isServerLikeValue(summary.installation_type) ||
             isServerLikeValue(summary.product_name));

  if (prefer_server) {
    if (mapped_server.has_value()) return *mapped_server;
    if (mapped_client.has_value()) return *mapped_client;
  } else {
    if (mapped_client.has_value()) return *mapped_client;
    if (mapped_server.has_value()) return *mapped_server;
  }

  return summary.product_name;
}

std::string resolveMountedPath(const std::string& device_path) {
#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    if (device_path == mounts[i].f_mntfromname) {
      return mounts[i].f_mntonname;
    }
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (device_path == entry->mnt_fsname) {
        const std::string mount_point = entry->mnt_dir;
        endmntent(mounts_file);
        return mount_point;
      }
    }
    endmntent(mounts_file);
  }
#endif
  return {};
}

std::vector<MountedRootInfo> listMountedRoots() {
  std::vector<MountedRootInfo> roots;
  std::unordered_set<std::string> unique_roots;
  const auto logger = GlobalLogger::get();

  auto append_root = [&](const std::string& root_path_raw,
                         const std::string& device_path_raw) {
    if (root_path_raw.empty()) return;
    const std::string root_path = ensureTrailingSlash(root_path_raw);
    std::error_code ec;
    if (!fs::is_directory(root_path, ec) || ec) {
      if (ec) {
        logger->debug("Пропуск точки монтирования \"{}\": {}", root_path_raw,
                      formatFilesystemError(ec));
      }
      return;
    }
    if (unique_roots.insert(root_path).second) {
      roots.push_back({device_path_raw, root_path});
    }
  };

#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    append_root(mounts[i].f_mntonname, mounts[i].f_mntfromname);
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (entry != nullptr && entry->mnt_dir != nullptr) {
        append_root(entry->mnt_dir,
                    entry->mnt_fsname != nullptr ? entry->mnt_fsname : "");
      }
    }
    endmntent(mounts_file);
  }
#endif

  return roots;
}

std::string normalizeDiskRoot(std::string disk_root) {
  if (isAutoDiskRootValue(disk_root)) {
    return {};
  }

  std::error_code ec;
  if (fs::is_directory(disk_root, ec) && !ec) {
    return ensureTrailingSlash(std::move(disk_root));
  }

  ec.clear();
  const bool is_device = fs::is_block_file(disk_root, ec) ||
                         fs::is_character_file(disk_root, ec);
  if (is_device && !ec) {
    const std::string mount_point = resolveMountedPath(disk_root);
    if (mount_point.empty()) {
      throw DiskNotMountedException(disk_root);
    }
    return ensureTrailingSlash(mount_point);
  }

  ec.clear();
  if (!fs::exists(disk_root, ec) || ec) {
    throw InvalidDiskRootException(
        disk_root, "путь не существует или недоступен для чтения");
  }

  throw InvalidDiskRootException(
      disk_root,
      "ожидался путь к каталогу (точке монтирования) или блочному устройству");
}

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

std::vector<std::pair<std::string, std::string>> collectRegistryHiveCandidates(
    const Config& config) {
  std::vector<std::pair<std::string, std::string>> candidates;
  std::unordered_set<std::string> seen;

  const auto add_candidate = [&](const std::string& label,
                                 std::string relative_path_raw) {
    trim(relative_path_raw);
    if (relative_path_raw.empty()) return;

    std::string normalized = normalizePathSeparators(std::move(relative_path_raw));
    trim(normalized);
    if (normalized.empty()) return;

    const std::string key = toLowerAscii(normalized);
    if (!seen.insert(key).second) return;

    candidates.emplace_back(label, std::move(normalized));
  };

  const std::string versions = config.getString("General", "Versions", "");
  for (auto parsed_versions = split(versions, ',');
       auto& version : parsed_versions) {
    trim(version);
    if (version.empty()) continue;

    add_candidate(
        version,
        getConfigValueWithSectionDefault(config, "OSInfoRegistryPaths", version));
  }

  if (config.hasKey("OSInfoRegistryPaths", std::string(kDefaultKey))) {
    add_candidate("Default",
                  config.getString("OSInfoRegistryPaths",
                                   std::string(kDefaultKey), ""));
  }

  return candidates;
}

ScopedDebugLevelOverride::ScopedDebugLevelOverride(const bool debug_enabled) {
  if (debug_enabled) return;

  logger_ = GlobalLogger::get();
  previous_level_ = logger_->level();
  if (previous_level_ <= spdlog::level::debug) {
    logger_->set_level(spdlog::level::info);
    active_ = true;
  }
}

ScopedDebugLevelOverride::~ScopedDebugLevelOverride() {
  if (active_ && logger_ != nullptr) {
    logger_->set_level(previous_level_);
  }
}

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path,
                                                std::string* error_reason) {
  return PathUtils::findPathCaseInsensitive(input_path, error_reason);
}

std::optional<WindowsRootSummary> detectWindowsRootSummary(
    const Config& config, const std::string& mount_root,
    std::string* error_reason) {
  const auto set_error = [&](const std::string& message) {
    if (error_reason != nullptr && error_reason->empty()) {
      *error_reason = message;
    }
  };

  auto parser = std::make_unique<RegistryAnalysis::RegistryParser>();
  const auto hive_candidates = collectRegistryHiveCandidates(config);

  for (const auto& [version_name, relative_path] : hive_candidates) {
    const fs::path expected_hive_path = fs::path(mount_root) / relative_path;

    std::string resolve_error;
    const auto resolved_hive_path =
        findPathCaseInsensitive(expected_hive_path, &resolve_error);
    if (!resolved_hive_path.has_value()) {
      if (!resolve_error.empty()) {
        set_error("hive \"" + expected_hive_path.string() +
                  "\" пропущен: " + resolve_error);
      }
      continue;
    }

    try {
      const auto values = parser->getKeyValues(
          resolved_hive_path->string(), "Microsoft/Windows NT/CurrentVersion");
      if (values.empty()) continue;

      WindowsRootSummary summary;
      for (const auto& value : values) {
        const std::string key = getLastPathComponent(value->getName(), '/');
        std::string data = value->getDataAsString();
        trim(data);

        if (key == "ProductName" && !data.empty()) {
          summary.product_name = data;
        } else if (key == "InstallationType" && !data.empty()) {
          summary.installation_type = data;
        } else if ((key == "CurrentBuild" || key == "CurrentBuildNumber") &&
                   !data.empty()) {
          summary.build = data;
        }
      }

      if (summary.product_name.empty()) {
        summary.product_name = "Windows";
      }

      const std::string system_hive_path =
          deriveSystemHivePathFromSoftwarePath(resolved_hive_path->string());
      if (!system_hive_path.empty()) {
        summary.system_product_type = tryReadSystemProductType(*parser,
                                                               system_hive_path);
      }
      summary.mapped_name = resolveMappedWindowsName(config, summary);
      if (summary.mapped_name.empty()) {
        summary.mapped_name = summary.product_name;
      }
      return summary;
    } catch (const std::exception& e) {
      set_error("ошибка чтения ОС для \"" + resolved_hive_path->string() +
                "\" (" + version_name + "): " + e.what());
    }
  }

  if (error_reason != nullptr && error_reason->empty()) {
    *error_reason = "не удалось прочитать сведения об ОС из SOFTWARE hive";
  }
  return std::nullopt;
}

std::string formatWindowsLabel(const WindowsRootSummary& summary) {
  const std::string& name =
      summary.mapped_name.empty() ? summary.product_name : summary.mapped_name;
  if (summary.build.empty()) return name;
  return name + " (build " + summary.build + ")";
}

void mergeRecoveryEvidenceToProcessData(
    const std::vector<RecoveryEvidence>& recovery_entries,
    std::unordered_map<std::string, ProcessInfo>& process_data) {
  for (const auto& evidence : recovery_entries) {
    std::string executable_path = evidence.executable_path;
    trim(executable_path);
    if (executable_path.empty()) continue;

    auto& info = process_data[executable_path];
    if (info.filename.empty()) {
      info.filename = executable_path;
    }

    appendEvidenceSource(info,
                         evidence.source.empty() ? "Recovery" : evidence.source);
    appendRecoveredFrom(
        info, evidence.recovered_from.empty() ? evidence.source
                                              : evidence.recovered_from);

    if (!evidence.timestamp.empty()) {
      info.run_times.push_back(evidence.timestamp);
      if (EvidenceUtils::isTimestampLike(evidence.timestamp)) {
        EvidenceUtils::updateTimestampMin(info.first_seen_utc, evidence.timestamp);
        EvidenceUtils::updateTimestampMax(info.last_seen_utc, evidence.timestamp);
      }
    }

    if (!evidence.tamper_flag.empty()) {
      appendTamperFlag(info, evidence.tamper_flag);
    }

    std::string timeline = "[" + (evidence.source.empty() ? "Recovery"
                                                          : evidence.source) +
                           "]";
    if (!evidence.timestamp.empty()) {
      timeline = evidence.timestamp + " " + timeline;
    }
    if (!evidence.details.empty()) {
      timeline += " " + evidence.details;
    }
    appendTimelineArtifact(info, timeline);
  }
}

bool hasInteractiveStdin() {
#if defined(__APPLE__) || defined(__linux__)
  return isatty(fileno(stdin)) != 0;
#else
  return true;
#endif
}


}  // namespace WindowsDiskAnalysis::Orchestrator::Detail
