#include "os_detection.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <string_view>
#include <utility>

#include "common/utils.hpp"
#include "errors/os_detection_exception.hpp"
#include "errors/registry_exception.hpp"
#include "os_info.hpp"

namespace WindowsVersion {
namespace {

constexpr std::string_view kDefaultKey = "Default";

std::string getConfigValueWithFallback(const Config& config,
                                       const std::string& section,
                                       const std::string& version_key,
                                       const std::string& defaults_section,
                                       const std::string& defaults_key) {
  if (config.hasKey(section, version_key)) {
    return config.getString(section, version_key, "");
  }

  if (config.hasKey(section, std::string(kDefaultKey))) {
    return config.getString(section, std::string(kDefaultKey), "");
  }

  if (config.hasKey(defaults_section, defaults_key)) {
    return config.getString(defaults_section, defaults_key, "");
  }

  return {};
}

}  // namespace

OSDetection::OSDetection(
    std::unique_ptr<RegistryAnalysis::IRegistryParser> parser, Config&& config,
    std::string device_root_path)
    : parser_(std::move(parser)),
      config_(config),
      device_root_path_(std::move(device_root_path)) {
  loadConfiguration();
}

void OSDetection::loadConfiguration() {
  const std::string version_list = config_.getString("General", "Versions", "");
  if (version_list.empty()) {
    throw OSDetectionException("отсутствуют \"Versions\" в разделе [General]");
  }

  auto version_names = split(version_list, ',');
  const auto logger = GlobalLogger::get();

  for (auto& name : version_names) {
    trim(name);
    if (name.empty()) continue;

    VersionConfig cfg;
    cfg.registry_file =
        getConfigValueWithFallback(config_, "OSInfoRegistryPaths", name,
                                   "OSInfoDefaults", "RegistryPath");
    cfg.registry_key = getConfigValueWithFallback(config_, "OSInfoHive", name,
                                                  "OSInfoDefaults",
                                                  "RegistryHive");

    const std::string config_keys =
        getConfigValueWithFallback(config_, "OSInfoKeys", name,
                                   "OSInfoDefaults", "RegistryKeys");
    if (!config_keys.empty()) {
      for (auto& key : split(config_keys, ',')) {
        trim(key);
        if (!key.empty()) {
          cfg.registry_keys.push_back(std::move(key));
        }
      }
    }

    if (!cfg.registry_file.empty() && !cfg.registry_key.empty() &&
        !cfg.registry_keys.empty()) {
      version_configs_.emplace(name, std::move(cfg));
      version_order_.push_back(name);
      logger->debug("Загруженная конфигурация для ключей \"{}\": \"{}\"", name,
                    version_configs_[name].registry_keys.size());
    }
  }

  const std::string keywords_str =
      config_.getString("OSKeywords", "DefaultServerKeywords", "");
  if (!keywords_str.empty()) {
    for (auto& kw : split(keywords_str, ',')) {
      trim(kw);
      if (!kw.empty()) {
        default_server_keywords_.push_back(std::move(kw));
      }
    }
  }

  auto load_build_mappings = [&](const std::string& section,
                                 std::map<uint32_t, std::string>& target) {
    try {
      for (const auto& key : config_.getKeysInSection(section)) {
        uint32_t build_num = 0;
        if (!tryParseUInt32(key, build_num)) {
          logger->warn("Недопустимый номер сборки: {}", key);
          continue;
        }
        std::string os_name = config_.getString(section, key, "");
        if (!os_name.empty()) {
          target[build_num] = std::move(os_name);
        }
      }
    } catch (...) {
    }
  };

  load_build_mappings("BuildMappingsClient", client_builds);
  load_build_mappings("BuildMappingsServer", server_builds);

  if (version_configs_.empty()) {
    throw OSDetectionException(
        "Не найдено допустимых конфигураций обнаружения операционной системы");
  }
}

OSInfo OSDetection::detect() {
  const auto logger = GlobalLogger::get();
  OSInfo info;
  bool detected = false;

  for (const auto& version_name : version_order_) {
    const auto& cfg = version_configs_.at(version_name);
    try {
      const std::string full_path = device_root_path_ + cfg.registry_file;

      if (const auto values =
              parser_->getKeyValues(full_path, cfg.registry_key);
          !values.empty()) {
        extractOSInfo(values, info, version_name);
        detected = true;
        break;
      }
    } catch (const std::exception& e) {
      logger->debug("Не удалось выполнить проверку реестра для \"{}\". {}",
                    version_name, e.what());
    }
  }

  if (!detected) {
    throw OSDetectionException(
        "Не удалось определить версию операционной системы");
  }

  determineFullOSName(info);
  info.ini_version = resolveIniVersion(info);

  logger->info("Версия Windows определена: \"{}\" (конфиг: {})",
               info.fullname_os, info.ini_version);

  return info;
}

void OSDetection::extractOSInfo(
    const std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>& values,
    OSInfo& info, const std::string& version_name) const {
  const auto& cfg = version_configs_.at(version_name);
  const auto logger = GlobalLogger::get();
  bool has_essential = false;

  std::map<std::string, std::string> value_map;
  for (const auto& data : values) {
    const std::string key_name = getLastPathComponent(data->getName(), '/');
    if (key_name.empty()) continue;

    try {
      if (data->getType() == RegistryAnalysis::RegistryValueType::REG_SZ ||
          data->getType() ==
              RegistryAnalysis::RegistryValueType::REG_EXPAND_SZ) {
        value_map[key_name] = data->getAsString();
      }
    } catch (...) {
      logger->warn("Ошибка при чтении значения реестра: {}", key_name);
    }
  }

  for (const auto& key : cfg.registry_keys) {
    auto it = value_map.find(key);
    if (it == value_map.end()) continue;

    const std::string& value = it->second;
    if (key == "ProductName") {
      info.product_name = value;
      has_essential = true;
    } else if (key == "CurrentVersion") {
      info.current_version = value;
      has_essential = true;
    } else if (key == "CurrentBuild" || key == "CurrentBuildNumber") {
      info.current_build = value;
      has_essential = true;
    } else if (key == "EditionID") {
      info.edition_id = value;
    } else if (key == "ReleaseId") {
      info.release_id = value;
    } else if (key == "DisplayVersion") {
      info.display_version = value;
    } else if (key == "CSDVersion") {
      info.release_id = value;
    }
  }

  if (!has_essential || info.product_name.empty() ||
      (info.current_version.empty() && info.current_build.empty())) {
    throw OSDetectionException(
        "Недостаточно данных для обнаружения операционной системы");
  }
}

void OSDetection::determineFullOSName(OSInfo& info) const {
  std::string name = info.product_name;
  const bool is_server = isServerSystem(info);

  if (!info.current_build.empty()) {
    uint32_t build_number = 0;
    if (tryParseUInt32(info.current_build, build_number)) {
      const auto& build_map = is_server ? server_builds : client_builds;
      if (const auto it = build_map.find(build_number); it != build_map.end()) {
        name = it->second;
      }
    }
  }

  std::ostringstream oss;
  oss << name;

  if (!info.edition_id.empty()) oss << " " << info.edition_id;
  if (!info.display_version.empty()) oss << " " << info.display_version;
  if (!info.release_id.empty()) oss << " " << info.release_id;
  if (!info.current_build.empty()) oss << " " << info.current_build;

  info.fullname_os = oss.str();
}

std::string OSDetection::resolveIniVersion(const OSInfo& info) const {
  const auto has_version = [&](const std::string_view name) {
    return version_configs_.contains(std::string(name));
  };

  const bool is_server = isServerSystem(info);
  if (is_server && has_version("WindowsServer")) {
    return "WindowsServer";
  }

  uint32_t build_number = 0;
  if (tryParseUInt32(info.current_build, build_number)) {
    if (build_number >= 22000 && has_version("Windows11")) return "Windows11";
    if (build_number >= 10240 && has_version("Windows10")) return "Windows10";
    if (build_number >= 9200 && has_version("Windows8")) return "Windows8";
    if (build_number >= 7600 && has_version("Windows7")) return "Windows7";
    if (build_number >= 6000 && has_version("WindowsVista")) {
      return "WindowsVista";
    }
    if (has_version("WindowsXP")) return "WindowsXP";
  }

  const std::string product_name = to_lower(info.product_name);
  if (product_name.find("windows server") != std::string::npos &&
      has_version("WindowsServer")) {
    return "WindowsServer";
  }
  if (product_name.find("windows 11") != std::string::npos &&
      has_version("Windows11")) {
    return "Windows11";
  }
  if (product_name.find("windows 10") != std::string::npos &&
      has_version("Windows10")) {
    return "Windows10";
  }
  if ((product_name.find("windows 8") != std::string::npos ||
       product_name.find("windows 8.1") != std::string::npos) &&
      has_version("Windows8")) {
    return "Windows8";
  }
  if (product_name.find("windows 7") != std::string::npos &&
      has_version("Windows7")) {
    return "Windows7";
  }
  if (product_name.find("vista") != std::string::npos &&
      has_version("WindowsVista")) {
    return "WindowsVista";
  }
  if (product_name.find("xp") != std::string::npos &&
      has_version("WindowsXP")) {
    return "WindowsXP";
  }

  if (!version_order_.empty()) {
    return version_order_.front();
  }
  throw OSDetectionException(
      "Не удалось сопоставить ОС с секцией конфигурации");
}

bool OSDetection::isServerSystem(const OSInfo& info) const {
  uint32_t build_number = 0;
  if (tryParseUInt32(info.current_build, build_number)) {
    const bool known_server = server_builds.contains(build_number);
    const bool known_client = client_builds.contains(build_number);
    if (known_server != known_client) return known_server;
  }

  const std::string product_name = to_lower(info.product_name);
  return product_name.find("server") != std::string::npos;
}

}
