#include "windows_disk_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include <spdlog/spdlog.h>

#include "parsers/event_log/evt/parser/parser.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "analysis/os/os_detection.hpp"
#include "common/utils.hpp"

#ifdef __APPLE__
#include <sys/mount.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <mntent.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;

namespace {

constexpr std::string_view kDefaultKey = "Default";

struct MountedRootInfo {
  std::string device_path;
  std::string mount_root;
};

struct WindowsRootSummary {
  std::string product_name;
  std::string installation_type;
  std::string system_product_type;
  std::string build;
  std::string mapped_name;
};

struct AutoSelectCandidate {
  MountedRootInfo mount;
  std::string os_label;
};

std::string ensureTrailingSlash(std::string path) {
  if (!path.empty() && path.back() != '/' && path.back() != '\\') {
    path.push_back('/');
  }
  return path;
}

std::string toLowerAscii(std::string text) {
  std::ranges::transform(text, text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
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
  std::ranges::replace(path, '\\', '/');
  return path;
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
      throw std::runtime_error("устройство \"" + disk_root +
                               "\" не смонтировано");
    }
    return ensureTrailingSlash(mount_point);
  }

  ec.clear();
  if (!fs::exists(disk_root, ec) || ec) {
    throw std::runtime_error("путь \"" + disk_root + "\" не существует");
  }

  throw std::runtime_error(
      "ожидался путь к каталогу (точке монтирования) или блочному устройству");
}

std::vector<std::string> parseListSetting(std::string value) {
  trim(value);
  if (value.empty()) return {};
  return split(value, ',');
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

class ScopedDebugLevelOverride {
 public:
  explicit ScopedDebugLevelOverride(bool debug_enabled) {
    if (debug_enabled) return;

    logger_ = GlobalLogger::get();
    previous_level_ = logger_->level();
    if (previous_level_ <= spdlog::level::debug) {
      logger_->set_level(spdlog::level::info);
      active_ = true;
    }
  }

  ~ScopedDebugLevelOverride() {
    if (active_ && logger_ != nullptr) {
      logger_->set_level(previous_level_);
    }
  }

 private:
  std::shared_ptr<spdlog::logger> logger_;
  spdlog::level::level_enum previous_level_ = spdlog::level::info;
  bool active_ = false;
};

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path,
                                                std::string* error_reason =
                                                    nullptr) {
  const auto set_error = [&](const std::string& message) {
    if (error_reason != nullptr) {
      *error_reason = message;
    }
  };

  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }
  if (ec) {
    set_error("не удалось проверить путь \"" + input_path.string() +
              "\": " + formatFilesystemError(ec));
  }

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) {
    set_error("не удалось получить текущий каталог: " + formatFilesystemError(ec));
    return std::nullopt;
  }

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
    if (ec) {
      set_error("ошибка доступа к \"" + direct_candidate.string() +
                "\": " + formatFilesystemError(ec));
      return std::nullopt;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec) {
      if (ec) {
        set_error("ошибка доступа к \"" + current.string() +
                  "\": " + formatFilesystemError(ec));
      } else {
        set_error("каталог \"" + current.string() + "\" не существует");
      }
      return std::nullopt;
    }
    if (!fs::is_directory(current, ec) || ec) {
      if (ec) {
        set_error("не удалось открыть каталог \"" + current.string() +
                  "\": " + formatFilesystemError(ec));
      } else {
        set_error("путь \"" + current.string() + "\" не является каталогом");
      }
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

    if (ec) {
      set_error("не удалось прочитать каталог \"" + current.string() +
                "\": " + formatFilesystemError(ec));
      return std::nullopt;
    }
    if (!matched) {
      set_error("компонент пути \"" + component +
                "\" не найден (с учетом регистра)");
      return std::nullopt;
    }
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) {
    return current;
  }
  if (ec) {
    set_error("ошибка проверки пути \"" + current.string() +
              "\": " + formatFilesystemError(ec));
  } else {
    set_error("путь \"" + current.string() + "\" не найден");
  }
  return std::nullopt;
}

std::optional<WindowsRootSummary> detectWindowsRootSummary(
    const Config& config, const std::string& mount_root,
    std::string* error_reason = nullptr) {
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

bool hasInteractiveStdin() {
#if defined(__APPLE__) || defined(__linux__)
  return isatty(fileno(stdin)) != 0;
#else
  return true;
#endif
}

}  // namespace

WindowsDiskAnalyzer::WindowsDiskAnalyzer(std::string  disk_root,
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

void WindowsDiskAnalyzer::detectOSVersion() {
  Config config(config_path_);
  loadLoggingOptions(config);
  std::string initial_validation_error;

  if (disk_root_.empty()) {
    initial_validation_error =
        "корень анализа не задан (включен режим auto-поиска)";
  } else {
    try {
      ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
      validateRegistryHivePresence(config);
    } catch (const std::runtime_error& e) {
      initial_validation_error = e.what();
    }
  }

  if (!initial_validation_error.empty()) {
    ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
    if (!tryAutoSelectWindowsRoot(config, initial_validation_error)) {
      throw std::runtime_error("Не удалось выбрать раздел Windows для анализа");
    }
  }

  std::unique_ptr<RegistryAnalysis::IRegistryParser> registry_parser =
      std::make_unique<RegistryAnalysis::RegistryParser>();

  WindowsVersion::OSDetection detector((std::move(registry_parser)),
                                       (std::move(config)), disk_root_);
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
    os_info_ = detector.detect();
  }
}

void WindowsDiskAnalyzer::validateRegistryHivePresence(
    const Config& config) const {
  const auto logger = GlobalLogger::get();
  std::vector<std::string> checked_paths;
  std::vector<std::string> checked_errors;
  if (hasRegistryHivePresence(config, disk_root_, &checked_paths,
                              &checked_errors)) {
    return;
  }

  logger->debug("Проверка hive-файлов для корня \"{}\" не прошла", disk_root_);
  if (!checked_paths.empty()) {
    std::ostringstream checked;
    for (size_t i = 0; i < checked_paths.size(); ++i) {
      if (i != 0) checked << ", ";
      checked << '"' << checked_paths[i] << '"';
    }
    logger->debug("Проверенные пути hive: {}", checked.str());
  } else {
    logger->debug("Проверенные пути hive отсутствуют в конфигурации");
  }

  if (!checked_errors.empty()) {
    const auto first_access_error = std::ranges::find_if(
        checked_errors, [](const std::string& error) {
          return containsAccessDenied(error);
        });
    if (first_access_error != checked_errors.end()) {
      logger->warn("Ошибка доступа к файловой системе при проверке hive");
    }
    logger->debug("Ошибки проверки путей hive: {}",
                  checked_errors.front());
  }

  throw std::runtime_error("В выбранном корне не найден hive-файл Windows");
}

bool WindowsDiskAnalyzer::hasRegistryHivePresence(
    const Config& config, const std::string& disk_root,
    std::vector<std::string>* checked_paths,
    std::vector<std::string>* checked_errors) const {
  if (checked_paths != nullptr) checked_paths->clear();
  if (checked_errors != nullptr) checked_errors->clear();
  if (disk_root.empty()) return false;

  const auto logger = GlobalLogger::get();
  const auto hive_candidates = collectRegistryHiveCandidates(config);
  std::unordered_set<std::string> checked_paths_set;
  checked_paths_set.reserve(hive_candidates.size());

  for (const auto& [version_name, relative_path] : hive_candidates) {
    if (relative_path.empty()) continue;

    const fs::path full_path = fs::path(disk_root) / relative_path;
    const std::string full_path_str = full_path.string();

    const bool is_new_path = checked_paths_set.insert(full_path_str).second;
    if (is_new_path && checked_paths != nullptr) {
      checked_paths->push_back(full_path_str);
    }

    std::string resolve_error;
    if (const auto resolved = findPathCaseInsensitive(full_path, &resolve_error);
        resolved.has_value()) {
      logger->debug("Найден hive-файл для определения ОС ({}): \"{}\"",
                    version_name, resolved->string());
      return true;
    }

    if (checked_errors != nullptr && !resolve_error.empty()) {
      checked_errors->push_back(full_path_str + " -> " + resolve_error);
    }
  }

  return false;
}

bool WindowsDiskAnalyzer::tryAutoSelectWindowsRoot(
    const Config& config, const std::string& initial_check_error) {
  const auto logger = GlobalLogger::get();
  logger->warn("Выбранный корень анализа не подходит, запускается авто-поиск");
  logger->debug("Причина переключения в режим авто-поиска: {}",
                initial_check_error);
  logger->info("Запуск авто-поиска Windows-раздела...");

  const std::vector<MountedRootInfo> mounted_roots = listMountedRoots();
  if (mounted_roots.empty()) {
    logger->error("Не удалось получить список смонтированных томов");
    return false;
  }

  std::string current_root = disk_root_;
  if (!current_root.empty()) {
    current_root = ensureTrailingSlash(std::move(current_root));
  }

  std::vector<AutoSelectCandidate> candidates;
  std::size_t access_denied_mounts = 0;

  for (const auto& mount : mounted_roots) {
    if (!current_root.empty() && mount.mount_root == current_root) continue;

    logger->debug("Проверка тома: \"{}\" ({})", mount.mount_root,
                  formatDeviceLabel(mount.device_path));

    std::vector<std::string> mount_errors;
    if (!hasRegistryHivePresence(config, mount.mount_root, nullptr,
                                 &mount_errors)) {
      if (std::ranges::any_of(mount_errors, [](const std::string& error) {
            return containsAccessDenied(error);
          })) {
        access_denied_mounts++;
        logger->debug("Том \"{}\" пропущен из-за ограничения доступа",
                      mount.mount_root);
      }
      continue;
    }

    std::string summary_error;
    std::string os_label = "Windows (версия не определена)";
    if (const auto summary =
            detectWindowsRootSummary(config, mount.mount_root, &summary_error);
        summary.has_value()) {
      os_label = formatWindowsLabel(*summary);
    } else if (!summary_error.empty()) {
      logger->debug("Не удалось определить версию ОС для \"{}\": {}",
                    mount.mount_root, summary_error);
    }

    candidates.push_back({mount, os_label});
  }

  if (candidates.empty()) {
    logger->error("Авто-поиск Windows-раздела не дал результата");
    if (access_denied_mounts > 0) {
      logger->warn("При авто-поиске нет доступа к {} томам",
                   access_denied_mounts);
    }
    logger->debug("Авто-поиск проверил {} смонтированных томов",
                  mounted_roots.size());
    return false;
  }

  if (candidates.size() == 1) {
    disk_root_ = candidates.front().mount.mount_root;
    logger->info("Windows-раздел выбран автоматически: \"{}\" ({}, {})",
                 disk_root_, formatDeviceLabel(candidates.front().mount.device_path),
                 candidates.front().os_label);
    return true;
  }

  std::cout << "\nНайдено несколько Windows-разделов. Выберите нужный:\n";
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    const auto& candidate = candidates[i];
    std::cout << (i + 1) << ". " << formatDeviceLabel(candidate.mount.device_path)
              << ", " << candidate.os_label
              << ", путь: " << candidate.mount.mount_root << '\n';
  }

  std::size_t selected_index = 0;
  if (!hasInteractiveStdin()) {
    logger->warn(
        "Запуск без интерактивной консоли; выбран первый найденный "
        "Windows-раздел");
  } else {
    while (true) {
      std::cout << "Введите номер [1-" << candidates.size() << "]: " << std::flush;
      std::string input;
      if (!std::getline(std::cin, input)) {
        logger->warn(
            "Не удалось прочитать выбор пользователя; выбран первый найденный "
            "Windows-раздел");
        break;
      }

      trim(input);
      uint32_t selected_number = 0;
      if (tryParseUInt32(input, selected_number) && selected_number >= 1 &&
          selected_number <= candidates.size()) {
        selected_index = static_cast<std::size_t>(selected_number - 1);
        break;
      }
      std::cout << "Некорректный выбор. Укажите число от 1 до "
                << candidates.size() << ".\n";
    }
  }

  const auto& selected = candidates[selected_index];
  disk_root_ = selected.mount.mount_root;
  logger->info("Выбран Windows-раздел: \"{}\" ({}, {})", disk_root_,
               formatDeviceLabel(selected.mount.device_path), selected.os_label);
  return true;
}

void WindowsDiskAnalyzer::loadLoggingOptions(const Config& config) {
  const auto logger = GlobalLogger::get();

  if (!config.hasSection("Logging")) {
    logger->debug(
        "Секция [Logging] не найдена, используются настройки debug по "
        "умолчанию");
    return;
  }

  auto readFlag = [&](const std::string& key, bool current_value) {
    try {
      return config.getBool("Logging", key, current_value);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Logging]/{}", key);
      logger->debug("Ошибка чтения [Logging]/{}: {}", key, e.what());
      return current_value;
    }
  };

  debug_options_.os_detection =
      readFlag("DebugOSDetection", debug_options_.os_detection);
  debug_options_.autorun = readFlag("DebugAutorun", debug_options_.autorun);
  debug_options_.prefetch = readFlag("DebugPrefetch", debug_options_.prefetch);
  debug_options_.eventlog = readFlag("DebugEventLog", debug_options_.eventlog);
  debug_options_.amcache = readFlag("DebugAmcache", debug_options_.amcache);

  logger->debug(
      "Загружены настройки [Logging]: OSDetection={}, Autorun={}, "
      "Prefetch={}, EventLog={}, Amcache={}",
      debug_options_.os_detection, debug_options_.autorun,
      debug_options_.prefetch, debug_options_.eventlog, debug_options_.amcache);
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
}

void WindowsDiskAnalyzer::ensureDirectoryExists(const std::string& path) {
  const fs::path dir_path = fs::path(path).parent_path();
  if (!dir_path.empty() && !exists(dir_path)) {
    create_directories(dir_path);
  }
}

CSVExportOptions WindowsDiskAnalyzer::loadCSVExportOptions() const {
  const auto logger = GlobalLogger::get();

  CSVExportOptions options;
  Config config(config_path_);
  if (!config.hasSection("CSVExport")) {
    logger->debug(
        "Секция [CSVExport] не найдена, используются значения по умолчанию");
    return options;
  }

  auto readSizeOption = [&](const std::string& key,
                            const std::size_t current_value) {
    try {
      const int value =
          config.getInt("CSVExport", key, static_cast<int>(current_value));
      if (value < 0) {
        logger->warn(
            "Параметр [CSVExport]/{} не может быть отрицательным ({}), "
            "оставлено значение {}",
            key, value, current_value);
        return current_value;
      }
      return static_cast<std::size_t>(value);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [CSVExport]/{} ({}), оставлено значение {}",
          key, e.what(), current_value);
      return current_value;
    }
  };

  auto readBoolOption = [&](const std::string& key, bool current_value) {
    try {
      return config.getBool("CSVExport", key, current_value);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [CSVExport]/{} ({}), оставлено значение {}",
          key, e.what(), current_value);
      return current_value;
    }
  };

  auto readListOption = [&](const std::string& key,
                            const std::vector<std::string>& current_value) {
    try {
      if (!config.hasKey("CSVExport", key)) return current_value;
      const std::string raw = config.getString("CSVExport", key, "");
      return parseListSetting(raw);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [CSVExport]/{} ({}), оставлено значение по "
          "умолчанию",
          key, e.what());
      return current_value;
    }
  };

  options.max_metric_names =
      readSizeOption("MetricMaxNames", options.max_metric_names);
  options.metric_skip_prefixes =
      readListOption("MetricSkipPrefixes", options.metric_skip_prefixes);
  options.metric_skip_contains =
      readListOption("MetricSkipContains", options.metric_skip_contains);
  options.metric_skip_exact =
      readListOption("MetricSkipExact", options.metric_skip_exact);
  options.drop_short_upper_tokens =
      readBoolOption("DropShortUpperTokens", options.drop_short_upper_tokens);
  options.short_upper_token_max_length = readSizeOption(
      "ShortUpperTokenMaxLength", options.short_upper_token_max_length);
  options.drop_hex_like_tokens =
      readBoolOption("DropHexLikeTokens", options.drop_hex_like_tokens);
  options.hex_like_min_length =
      readSizeOption("HexLikeMinLength", options.hex_like_min_length);
  options.drop_upper_alnum_tokens =
      readBoolOption("DropUpperAlnumTokens", options.drop_upper_alnum_tokens);
  options.upper_alnum_min_length =
      readSizeOption("UpperAlnumMinLength", options.upper_alnum_min_length);

  logger->debug(
      "Загружены настройки [CSVExport]: MetricMaxNames={}, Prefixes={}, "
      "Contains={}, Exact={}",
      options.max_metric_names, options.metric_skip_prefixes.size(),
      options.metric_skip_contains.size(), options.metric_skip_exact.size());

  return options;
}

void WindowsDiskAnalyzer::analyze(const std::string& output_path) {
  // 1. Сбор данных об автозагрузке
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.autorun);
    autorun_entries_ = autorun_analyzer_->collect(disk_root_);
  }

  // 2. Сбор данных из Amcache.hve
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.amcache);
    amcache_entries_ = amcache_analyzer_->collect(disk_root_);
  }

  // 3. Сбор данных из Prefetch
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
  }

  // 4. Анализ журналов событий
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.eventlog);
    eventlog_analyzer_->collect(disk_root_, process_data_, network_connections_);
  }

  // 5. Экспорт результатов (обновленный вызов)
  ensureDirectoryExists(output_path);
  const CSVExportOptions csv_export_options = loadCSVExportOptions();
  CSVExporter::exportToCSV(output_path, autorun_entries_, process_data_,
                           network_connections_, amcache_entries_,
                           csv_export_options);
}
