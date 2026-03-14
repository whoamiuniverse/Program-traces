/// @file windows_disk_analyzer_helpers_windows_root.cpp
/// @brief Helper-функции оркестратора для извлечения сведений об ОС и hive-кандидатов.

#include "windows_disk_analyzer_helpers.hpp"

#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "common/utils.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis::Orchestrator::Detail {

namespace fs = std::filesystem;

namespace {
constexpr std::string_view kDefaultKey = "Default";
}  // namespace

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

    std::string normalized =
        normalizePathSeparators(std::move(relative_path_raw));
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

}  // namespace WindowsDiskAnalysis::Orchestrator::Detail
