/// @file recent_apps_collector.hpp
/// @brief Коллектор артефактов RecentApps.
#pragma once
#include <map>
#include <unordered_map>
#include <string>
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class RecentAppsCollector
/// @brief Собирает RecentApps из NTUSER.DAT пользователей.
class RecentAppsCollector final : public IExecutionArtifactCollector {
 public:
  void collect(const ExecutionEvidenceContext& ctx,
               std::unordered_map<std::string, ProcessInfo>& process_data) override;
};

}  // namespace WindowsDiskAnalysis
