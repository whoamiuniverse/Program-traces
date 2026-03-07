/// @file services_collector.cpp
/// @brief Реализация ServicesCollector.
#include "services_collector.hpp"

#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::toLowerAscii;

void ServicesCollector::collect(const ExecutionEvidenceContext& ctx,
                                std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_services) return;
  if (ctx.system_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::string& system_hive_path = ctx.system_hive_path;
  const std::string control_set_root =
      resolveControlSetRoot(local_parser, system_hive_path, "CurrentControlSet");
  if (control_set_root.empty()) {
    logger->debug("Services: не удалось определить активный ControlSet");
    return;
  }

  std::string services_root = ctx.config.services_root_path;
  const std::string marker = "CurrentControlSet/";
  if (services_root.rfind(marker, 0) == 0) {
    services_root.replace(0, marker.size(), control_set_root + "/");
  }

  std::vector<std::string> service_keys;
  try {
    service_keys = local_parser.listSubkeys(system_hive_path, services_root);
  } catch (const std::exception& e) {
    logger->debug("Services пропущен: {}", e.what());
    return;
  }

  auto start_type_to_string = [](const uint32_t start_type) -> std::string {
    switch (start_type) {
      case 0:
        return "Boot";
      case 1:
        return "System";
      case 2:
        return "Auto";
      case 3:
        return "Manual";
      case 4:
        return "Disabled";
      default:
        return std::to_string(start_type);
    }
  };

  std::size_t collected = 0;
  std::unordered_set<std::string> seen;
  for (const std::string& service_name : service_keys) {
    if (collected >= ctx.config.max_candidates_per_source) break;

    const std::string service_key = services_root + "/" + service_name;
    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
    try {
      values = local_parser.getKeyValues(system_hive_path, service_key);
    } catch (...) {
      continue;
    }

    std::string image_path;
    std::string service_dll;
    std::string display_name;
    std::string object_name;
    std::string service_type;
    std::string start_mode;

    for (const auto& value : values) {
      const std::string value_name =
          toLowerAscii(getLastPathComponent(value->getName(), '/'));
      try {
        if (value_name == "imagepath") {
          image_path = trim_copy(value->getDataAsString());
        } else if (value_name == "servicedll") {
          service_dll = trim_copy(value->getDataAsString());
        } else if (value_name == "displayname") {
          display_name = trim_copy(value->getDataAsString());
        } else if (value_name == "objectname") {
          object_name = trim_copy(value->getDataAsString());
        } else if (value_name == "start") {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
              value->getType() ==
                  RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN) {
            start_mode = start_type_to_string(value->getAsDword());
          } else {
            start_mode = trim_copy(value->getDataAsString());
          }
        } else if (value_name == "type") {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
              value->getType() ==
                  RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN) {
            service_type = std::to_string(value->getAsDword());
          } else {
            service_type = trim_copy(value->getDataAsString());
          }
        }
      } catch (...) {
      }
    }

    std::vector<std::string> service_targets;
    if (auto executable = extractExecutableFromCommand(image_path);
        executable.has_value()) {
      appendUniqueToken(service_targets, *executable);
    }
    if (auto executable = extractExecutableFromCommand(service_dll);
        executable.has_value()) {
      appendUniqueToken(service_targets, *executable);
    }

    if (service_targets.empty()) {
      continue;
    }

    std::ostringstream details;
    details << "service=" << service_name;
    if (!display_name.empty()) details << ", display=" << display_name;
    if (!start_mode.empty()) details << ", start=" << start_mode;
    if (!service_type.empty()) details << ", type=" << service_type;
    if (!object_name.empty()) details << ", account=" << object_name;
    if (!image_path.empty()) details << ", image=" << image_path;
    if (!service_dll.empty()) details << ", servicedll=" << service_dll;

    for (const std::string& target : service_targets) {
      if (collected >= ctx.config.max_candidates_per_source) break;

      const std::string dedupe_key = toLowerAscii(service_name + "|" + target);
      if (!seen.insert(dedupe_key).second) continue;

      addExecutionEvidence(process_data, target, "Service", "", details.str());
      collected++;
    }
  }

  logger->info("Services: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
