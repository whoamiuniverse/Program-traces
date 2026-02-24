#include "os_detection.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <utility>

#include "../../../core/exceptions/os_detection_exception.hpp"
#include "../../../core/exceptions/registry_exception.hpp"
#include "../../../utils/utils.hpp"
#include "os_info.hpp"

namespace WindowsVersion {

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
    cfg.registry_file = config_.getString("OSInfoRegistryPaths", name, "");
    cfg.registry_key = config_.getString("OSInfoHive", name, "");

    const std::string config_keys = config_.getString("OSInfoKeys", name, "");
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
        try {
          uint32_t build_num = std::stoul(key);
          std::string os_name = config_.getString(section, key, "");
          if (!os_name.empty()) {
            target[build_num] = std::move(os_name);
          }
        } catch (...) {
          logger->warn("Недопустимый номер сборки: {}", key);
        }
      }
    } catch (...) {
    }
  };

  load_build_mappings("BuildMappingsClient", client_builds);
  load_build_mappings("BuildMappingsServer", server_builds);

  if (version_configs_.empty()) {
    throw OSDetectionException(
        "не найдено допустимых конфигураций обнаружения операционной системы");
  }
}

OSInfo OSDetection::detect() {
  const auto logger = GlobalLogger::get();
  OSInfo info;
  bool detected = false;

  for (const auto& [version_name, cfg] : version_configs_) {
    try {
      const std::string full_path = device_root_path_ + cfg.registry_file;
      const auto values = parser_->getKeyValues(full_path, cfg.registry_key);

      if (!values.empty()) {
        extractOSInfo(values, info, version_name);
        info.ini_version = version_name;
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
        "не удалось определить версию операционной системы");
  }

  determineFullOSName(info);

  logger->info("Версия Windows определена: \"{}\"", info.fullname_os);

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
        "недостаточно данных для обнаружения операционной системы");
  }
}

void OSDetection::determineFullOSName(OSInfo& info) const {
  std::string name = info.product_name;
  const bool is_server = isServerSystem(info);

  if (!info.current_build.empty()) {
    try {
      uint32_t build_number = std::stoul(info.current_build);
      const auto& build_map = is_server ? server_builds : client_builds;
      if (const auto it = build_map.find(build_number); it != build_map.end()) {
        name = it->second;
      }
    } catch (...) {
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

bool OSDetection::isServerSystem(const OSInfo& info) const {
  auto contains_keyword = [&](const std::string& text) {
    return std::ranges::any_of(default_server_keywords_,
                               [&](const std::string& kw) {
                                 return text.find(kw) != std::string::npos;
                               });
  };

  return contains_keyword(info.product_name) ||
         contains_keyword(info.edition_id);
}

}
