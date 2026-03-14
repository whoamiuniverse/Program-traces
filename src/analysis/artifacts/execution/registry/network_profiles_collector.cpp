/// @file network_profiles_collector.cpp
/// @brief Реализация NetworkProfilesCollector.
#include "network_profiles_collector.hpp"

#include <iomanip>
#include <unordered_map>
#include <sstream>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::toLowerAscii;

void NetworkProfilesCollector::collect(const ExecutionEvidenceContext& ctx,
                                       std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_network_profiles) return;
  if (ctx.software_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::string& software_hive_path = ctx.software_hive_path;

  std::vector<std::string> profile_subkeys;
  try {
    profile_subkeys =
        local_parser.listSubkeys(software_hive_path, ctx.config.network_profiles_root_key);
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "NetworkProfiles пропущен: {}", e.what());
    return;
  }

  std::size_t collected = 0;
  std::size_t signature_collected = 0;
  const std::string network_context_key = networkContextProcessKey();

  auto format_mac_from_binary = [](const std::vector<uint8_t>& bytes) {
    if (bytes.empty() || bytes.size() > 16) return std::string{};
    std::ostringstream stream;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
      if (index > 0) stream << ":";
      stream << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<int>(bytes[index]);
    }
    std::string formatted = stream.str();
    std::ranges::transform(formatted, formatted.begin(),
                           [](const unsigned char ch) {
                             return static_cast<char>(std::toupper(ch));
                           });
    return formatted;
  };

  for (const std::string& profile_subkey : profile_subkeys) {
    if (collected >= ctx.config.max_candidates_per_source) break;

    const std::string profile_key =
        ctx.config.network_profiles_root_key + "/" + profile_subkey;
    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
    try {
      values = local_parser.getKeyValues(software_hive_path, profile_key);
    } catch (...) {
      continue;
    }

    std::string profile_name;
    std::string description;
    std::string category;
    std::string created_timestamp;
    std::string last_connected_timestamp;

    for (const auto& value : values) {
      const std::string value_name =
          toLowerAscii(getLastPathComponent(value->getName(), '/'));
      if (value_name.empty()) continue;

      try {
        if (value_name == "profilename") {
          profile_name = trim_copy(value->getDataAsString());
        } else if (value_name == "description") {
          description = trim_copy(value->getDataAsString());
        } else if (value_name == "category") {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
              value->getType() ==
                  RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN) {
            category =
                normalizeNetworkProfileCategory(std::to_string(value->getAsDword()));
          } else {
            category = normalizeNetworkProfileCategory(value->getDataAsString());
          }
        } else if (value_name == "datecreated" &&
                   value->getType() ==
                       RegistryAnalysis::RegistryValueType::REG_BINARY) {
          const auto timestamp = parseRegistrySystemTime(value->getAsBinary());
          if (timestamp.has_value()) {
            created_timestamp = *timestamp;
          }
        } else if (value_name == "datelastconnected" &&
                   value->getType() ==
                       RegistryAnalysis::RegistryValueType::REG_BINARY) {
          const auto timestamp = parseRegistrySystemTime(value->getAsBinary());
          if (timestamp.has_value()) {
            last_connected_timestamp = *timestamp;
          }
        }
      } catch (...) {
      }
    }

    if (profile_name.empty() && description.empty() && category.empty()) continue;

    const std::string timestamp =
        !last_connected_timestamp.empty() ? last_connected_timestamp
                                          : created_timestamp;

    std::ostringstream details;
    details << "profile="
            << (profile_name.empty() ? std::string("N/A") : profile_name)
            << ", guid=" << profile_subkey;
    if (!category.empty()) {
      details << ", category=" << category;
    }
    if (!description.empty()) {
      details << ", description=" << description;
    }
    if (!created_timestamp.empty()) {
      details << ", created=" << created_timestamp;
    }

    addExecutionEvidence(process_data, network_context_key, "NetworkProfile",
                         timestamp, details.str());
    collected++;
  }

  if (!ctx.config.network_signature_roots.empty() &&
      collected < ctx.config.max_candidates_per_source) {
    for (std::string signature_root : ctx.config.network_signature_roots) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      if (signature_root.empty()) continue;

      std::vector<std::string> signature_subkeys;
      try {
        signature_subkeys = local_parser.listSubkeys(software_hive_path, signature_root);
      } catch (...) {
        continue;
      }

      for (const std::string& signature_subkey : signature_subkeys) {
        if (collected >= ctx.config.max_candidates_per_source) break;

        const std::string signature_key = signature_root + "/" + signature_subkey;
        std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
        try {
          values = local_parser.getKeyValues(software_hive_path, signature_key);
        } catch (...) {
          continue;
        }

        std::string profile_guid;
        std::string dns_suffix;
        std::string first_network;
        std::string gateway_mac;

        for (const auto& value : values) {
          const std::string value_name =
              toLowerAscii(getLastPathComponent(value->getName(), '/'));
          if (value_name.empty()) continue;

          try {
            if (value_name == "profileguid") {
              profile_guid = trim_copy(value->getDataAsString());
            } else if (value_name == "dnssuffix") {
              dns_suffix = trim_copy(value->getDataAsString());
            } else if (value_name == "firstnetwork") {
              first_network = trim_copy(value->getDataAsString());
            } else if (value_name == "defaultgatewaymac" &&
                       value->getType() ==
                           RegistryAnalysis::RegistryValueType::REG_BINARY) {
              gateway_mac = format_mac_from_binary(value->getAsBinary());
            }
          } catch (...) {
          }
        }

        if (profile_guid.empty() && dns_suffix.empty() && first_network.empty() &&
            gateway_mac.empty()) {
          continue;
        }

        std::ostringstream details;
        details << "signature=" << signature_subkey;
        if (!profile_guid.empty()) details << ", profile_guid=" << profile_guid;
        if (!dns_suffix.empty()) details << ", dns_suffix=" << dns_suffix;
        if (!first_network.empty()) details << ", first_network=" << first_network;
        if (!gateway_mac.empty()) details << ", gateway_mac=" << gateway_mac;
        details << ", source_root=" << signature_root;

        addExecutionEvidence(process_data, network_context_key, "NetworkProfile",
                            "", details.str());
        collected++;
        signature_collected++;
      }
    }
  }

  logger->info("NetworkProfiles: profiles={}, signatures={}, total={}",
               collected - signature_collected, signature_collected, collected);
}

}  // namespace WindowsDiskAnalysis
