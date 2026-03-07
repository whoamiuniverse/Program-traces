/// @file firewall_rules_collector.cpp
/// @brief Реализация FirewallRulesCollector.
#include "firewall_rules_collector.hpp"

#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::toLowerAscii;

void FirewallRulesCollector::collect(const ExecutionEvidenceContext& ctx,
                                     std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_firewall_rules) return;
  if (ctx.system_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::string& system_hive_path = ctx.system_hive_path;
  const std::string control_set_root =
      resolveControlSetRoot(local_parser, system_hive_path, "CurrentControlSet");
  if (control_set_root.empty()) {
    logger->debug("FirewallRules: не удалось определить активный ControlSet");
    return;
  }

  std::size_t collected = 0;
  std::unordered_set<std::string> seen_rules;
  const std::string network_context_key = networkContextProcessKey();

  for (std::string key_path : ctx.config.firewall_rules_keys) {
    if (collected >= ctx.config.max_candidates_per_source) break;

    const std::string marker = "CurrentControlSet/";
    if (key_path.rfind(marker, 0) == 0) {
      key_path.replace(0, marker.size(), control_set_root + "/");
    }

    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
    try {
      values = local_parser.getKeyValues(system_hive_path, key_path);
    } catch (const std::exception& e) {
      logger->debug("FirewallRules key пропущен \"{}\": {}", key_path, e.what());
      continue;
    }

    for (const auto& value : values) {
      if (collected >= ctx.config.max_candidates_per_source) break;

      const std::string rule_id = getLastPathComponent(value->getName(), '/');
      if (rule_id.empty()) continue;

      std::string raw_rule_data = value->getDataAsString();
      trim(raw_rule_data);
      if (raw_rule_data.empty()) continue;

      auto fields = parseFirewallRuleData(raw_rule_data);
      const auto get_field = [&](const std::initializer_list<std::string_view>& keys)
          -> std::string {
        for (const std::string_view key : keys) {
          if (const auto it = fields.find(std::string(key)); it != fields.end()) {
            return trim_copy(it->second);
          }
        }
        return {};
      };

      const std::string rule_name = get_field({"name", "description"});
      const std::string application =
          get_field({"app", "application", "applicationname", "image",
                     "imagepath"});
      const std::string direction =
          normalizeFirewallDirection(get_field({"dir", "direction"}));
      const std::string action = normalizeFirewallAction(get_field({"action"}));
      const std::string protocol =
          normalizeFirewallProtocol(get_field({"protocol"}));
      const std::string local_ports =
          get_field({"lport", "localport", "localports", "lports"});
      const std::string remote_ports =
          get_field({"rport", "remoteport", "remoteports", "rports"});
      const std::string profile = get_field({"profile", "profiles"});
      const std::string active = get_field({"active", "enabled"});
      const std::string service = get_field({"svc", "service"});
      bool is_active = true;
      if (!active.empty()) {
        const std::string active_lower = toLowerAscii(trim_copy(active));
        if (active_lower == "false" || active_lower == "0" ||
            active_lower == "no") {
          is_active = false;
        }
      }
      if (!ctx.config.include_inactive_firewall_rules && !is_active) {
        continue;
      }

      const std::string dedupe_key = toLowerAscii(
          rule_id + "|" + rule_name + "|" + application + "|" + direction + "|" +
          action + "|" + protocol + "|" + local_ports + "|" + remote_ports);
      if (!seen_rules.insert(dedupe_key).second) continue;

      std::vector<std::string> sid_candidates =
          extractSidCandidatesFromLine(raw_rule_data);

      std::ostringstream details;
      details << "rule="
              << (rule_name.empty() ? std::string("N/A") : rule_name)
              << ", id=" << rule_id;
      if (!application.empty()) details << ", app=" << application;
      if (!action.empty()) details << ", action=" << action;
      if (!direction.empty()) details << ", dir=" << direction;
      if (!protocol.empty()) details << ", protocol=" << protocol;
      if (!local_ports.empty()) details << ", lport=" << local_ports;
      if (!remote_ports.empty()) details << ", rport=" << remote_ports;
      if (!profile.empty()) details << ", profile=" << profile;
      if (!active.empty()) details << ", active=" << active;
      if (!service.empty()) details << ", service=" << service;

      if (!sid_candidates.empty()) {
        details << ", sid=" << sid_candidates.front();
        if (sid_candidates.size() > 1) {
          details << ", owner_sids=";
          for (std::size_t index = 0; index < sid_candidates.size(); ++index) {
            if (index > 0) details << "|";
            details << sid_candidates[index];
          }
        }
      }

      std::string target_process = network_context_key;
      if (!application.empty()) {
        if (auto executable = tryExtractExecutableFromDecoratedText(application);
            executable.has_value()) {
          target_process = *executable;
        }
      }

      addExecutionEvidence(process_data, target_process, "FirewallRule", "",
                          details.str());
      collected++;
    }
  }

  logger->info("FirewallRules: добавлено {} запись(ей)", collected);
}

}  // namespace WindowsDiskAnalysis
