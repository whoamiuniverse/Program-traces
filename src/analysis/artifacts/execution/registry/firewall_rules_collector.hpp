/// @file firewall_rules_collector.hpp
/// @brief Collector for Windows Firewall rules execution artifacts.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class FirewallRulesCollector
/// @brief Collects Windows Firewall rule artifacts from the SYSTEM registry hive.
///
/// @details Reads firewall rules from all profiles (Default, Domain, Public, Standard)
/// as configured in @c ctx.config.firewall_rules_keys. Optionally includes inactive
/// rules when @c ctx.config.include_inactive_firewall_rules is @c true.
/// Skipped entirely when @c ctx.config.enable_firewall_rules is @c false.
class FirewallRulesCollector final : public IExecutionArtifactCollector {
 public:
  /// @brief Collects firewall rule artifacts from the SYSTEM hive.
  /// @param ctx          Analysis context containing disk paths, config, and parallelism limits.
  /// @param process_data Map of processes to enrich (updated in place).
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
