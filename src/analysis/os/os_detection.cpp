#include "os_detection.hpp"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>

#include "common/config_utils.hpp"
#include "common/utils.hpp"
#include "errors/os_detection_exception.hpp"
#include "errors/registry_exception.hpp"
#include "os_info.hpp"

namespace WindowsVersion {
namespace {
namespace fs = std::filesystem;

std::optional<std::string> findMappedNameByBuildThreshold(
    const std::map<uint32_t, std::string>& build_mappings,
    uint32_t build_number) {
  if (build_mappings.empty()) return std::nullopt;

  const auto upper_it = build_mappings.upper_bound(build_number);
  if (upper_it == build_mappings.begin()) return std::nullopt;

  const auto it = std::prev(upper_it);
  return it->second;
}

std::string resolveIniVersionFromMappedName(std::string mapped_name) {
  const std::string normalized = to_lower(std::move(mapped_name));
  if (normalized.find("server") != std::string::npos) return "WindowsServer";
  if (normalized.find("windows 11") != std::string::npos) return "Windows11";
  if (normalized.find("windows 10") != std::string::npos) return "Windows10";
  if (normalized.find("windows 8") != std::string::npos) return "Windows8";
  if (normalized.find("windows 7") != std::string::npos) return "Windows7";
  if (normalized.find("vista") != std::string::npos) return "WindowsVista";
  if (normalized.find("xp") != std::string::npos) return "WindowsXP";
  return {};
}

bool mappedNameMatchesServerClass(const std::string& mapped_name,
                                  bool is_server) {
  const std::string mapped_ini = resolveIniVersionFromMappedName(mapped_name);
  if (mapped_ini.empty()) return true;
  if (is_server) return mapped_ini == "WindowsServer";
  return mapped_ini != "WindowsServer";
}

std::string normalizePathSeparators(std::string path) {
  std::ranges::replace(path, '\\', '/');
  return path;
}

std::string deriveSystemHivePathFromSoftwarePath(std::string software_hive_path) {
  software_hive_path = normalizePathSeparators(std::move(software_hive_path));
  if (software_hive_path.empty()) return {};

  fs::path hive_path(software_hive_path);
  const std::string filename = to_lower(hive_path.filename().string());
  if (filename == "system") {
    return hive_path.generic_string();
  }
  if (filename != "software") {
    return {};
  }

  hive_path.replace_filename("SYSTEM");
  return hive_path.generic_string();
}

bool isServerProductType(std::string product_type) {
  const std::string lowered = to_lower(std::move(product_type));
  return lowered == "servernt" || lowered == "lanmannt";
}

bool isClientProductType(std::string product_type) {
  const std::string lowered = to_lower(std::move(product_type));
  return lowered == "winnt";
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
    cfg.registry_file = WindowsDiskAnalysis::ConfigUtils::
        getWithSectionDefaultAndFallback(
        config_, "OSInfoRegistryPaths", name, "OSInfoDefaults",
        "RegistryPath");
    cfg.registry_key = WindowsDiskAnalysis::ConfigUtils::
        getWithSectionDefaultAndFallback(
        config_, "OSInfoHive", name, "OSInfoDefaults", "RegistryHive");

    const std::string config_keys =
        WindowsDiskAnalysis::ConfigUtils::getWithSectionDefaultAndFallback(
            config_, "OSInfoKeys", name, "OSInfoDefaults", "RegistryKeys");
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
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Загруженная конфигурация для ключей \"{}\": \"{}\"", name,
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
        const std::string system_hive_relative =
            resolveSystemHiveRelativePath(version_name, cfg);
        if (!system_hive_relative.empty()) {
          enrichFromSystemHive(device_root_path_ + system_hive_relative, info);
        }
        detected = true;
        break;
      }
    } catch (const std::exception& e) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Не удалось выполнить проверку реестра для \"{}\". {}",
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
    } else if (key == "InstallationType") {
      info.installation_type = value;
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
  std::string name = info.product_name.empty() ? "Windows" : info.product_name;
  const bool is_server = isServerSystem(info);

  if (!info.current_build.empty()) {
    uint32_t build_number = 0;
    if (tryParseUInt32(info.current_build, build_number)) {
      const auto& primary_map = is_server ? server_builds : client_builds;
      const auto& secondary_map = is_server ? client_builds : server_builds;

      if (const auto mapped_primary =
              findMappedNameByBuildThreshold(primary_map, build_number);
          mapped_primary.has_value()) {
        name = *mapped_primary;
      } else if (const auto mapped_secondary =
                     findMappedNameByBuildThreshold(secondary_map,
                                                    build_number);
                 mapped_secondary.has_value() &&
                 mappedNameMatchesServerClass(*mapped_secondary, is_server)) {
        name = *mapped_secondary;
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

  uint32_t build_number = 0;
  if (tryParseUInt32(info.current_build, build_number)) {
    const auto& primary_map = is_server ? server_builds : client_builds;
    const auto& secondary_map = is_server ? client_builds : server_builds;

    if (const auto mapped =
            findMappedNameByBuildThreshold(primary_map, build_number);
        mapped.has_value()) {
      const std::string mapped_ini = resolveIniVersionFromMappedName(*mapped);
      if (!mapped_ini.empty() && has_version(mapped_ini)) {
        return mapped_ini;
      }
    }

    if (const auto mapped =
            findMappedNameByBuildThreshold(secondary_map, build_number);
        mapped.has_value() &&
        mappedNameMatchesServerClass(*mapped, is_server)) {
      const std::string mapped_ini = resolveIniVersionFromMappedName(*mapped);
      if (!mapped_ini.empty() && has_version(mapped_ini)) {
        return mapped_ini;
      }
    }
  }

  if (is_server && has_version("WindowsServer")) {
    return "WindowsServer";
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

std::string OSDetection::resolveSystemHiveRelativePath(
    const std::string& version_name, const VersionConfig& cfg) const {
  std::string configured_path =
      WindowsDiskAnalysis::ConfigUtils::getWithSectionDefaultAndFallback(
          config_, "OSInfoSystemRegistryPaths", version_name,
          "OSInfoSystemDefaults", "RegistryPath");
  trim(configured_path);
  if (!configured_path.empty()) {
    return normalizePathSeparators(std::move(configured_path));
  }

  return deriveSystemHivePathFromSoftwarePath(cfg.registry_file);
}

std::optional<uint32_t> OSDetection::readCurrentControlSetIndex(
    const std::string& system_hive_path) const {
  try {
    const auto current_value =
        parser_->getSpecificValue(system_hive_path, "Select/Current");
    if (!current_value) return std::nullopt;

    switch (current_value->getType()) {
      case RegistryAnalysis::RegistryValueType::REG_DWORD:
      case RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN:
        return current_value->getAsDword();
      case RegistryAnalysis::RegistryValueType::REG_QWORD: {
        const uint64_t value = current_value->getAsQword();
        if (value <= std::numeric_limits<uint32_t>::max()) {
          return static_cast<uint32_t>(value);
        }
        break;
      }
      default:
        break;
    }

    std::string text_value = current_value->getDataAsString();
    trim(text_value);
    uint32_t parsed = 0;
    if (tryParseUInt32(text_value, parsed)) {
      return parsed;
    }
  } catch (...) {
  }

  return std::nullopt;
}

void OSDetection::enrichFromSystemHive(const std::string& system_hive_path,
                                       OSInfo& info) const {
  const auto logger = GlobalLogger::get();

  auto read_product_type =
      [&](const std::string& value_path) -> std::optional<std::string> {
    const auto value = parser_->getSpecificValue(system_hive_path, value_path);
    if (!value) return std::nullopt;
    std::string product_type = value->getDataAsString();
    trim(product_type);
    if (product_type.empty()) return std::nullopt;
    return product_type;
  };

  try {
    if (const auto product_type = read_product_type(
            "CurrentControlSet/Control/ProductOptions/ProductType");
        product_type.has_value()) {
      info.system_product_type = *product_type;
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "ProductType из SYSTEM hive: {}", info.system_product_type);
      return;
    }

    const auto current_control_set = readCurrentControlSetIndex(system_hive_path);
    if (!current_control_set.has_value()) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
          "Не удалось определить Select/Current в SYSTEM hive: \"{}\"",
          system_hive_path);
      return;
    }

    std::ostringstream control_set_path;
    control_set_path << "ControlSet" << std::setw(3) << std::setfill('0')
                     << *current_control_set
                     << "/Control/ProductOptions/ProductType";
    if (const auto product_type = read_product_type(control_set_path.str());
        product_type.has_value()) {
      info.system_product_type = *product_type;
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "ProductType из SYSTEM hive: {}", info.system_product_type);
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Не удалось прочитать ProductType из SYSTEM hive \"{}\": {}",
                  system_hive_path, e.what());
  }
}

bool OSDetection::isServerSystem(const OSInfo& info) const {
  if (!info.system_product_type.empty()) {
    if (isServerProductType(info.system_product_type)) return true;
    if (isClientProductType(info.system_product_type)) return false;
  }

  const std::string installation_type = to_lower(info.installation_type);
  if (installation_type.find("server") != std::string::npos) return true;
  if (installation_type.find("client") != std::string::npos) return false;

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
