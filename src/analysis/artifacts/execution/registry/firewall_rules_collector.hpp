/// @file firewall_rules_collector.hpp
/// @brief Коллектор артефактов FirewallRules.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class FirewallRulesCollector
/// @brief Собирает артефакты firewall-правил из SYSTEM hive.
class FirewallRulesCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
