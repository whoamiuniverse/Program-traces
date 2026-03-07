/// @file muicache_collector.cpp
/// @brief Реализация MuiCacheCollector.
#include "muicache_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>
#include <string_view>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::toLowerAscii;

void MuiCacheCollector::collect(const ExecutionEvidenceContext& ctx,
                                std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_muicache) return;
  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  if (user_hives.empty()) return;

  std::size_t collected = 0;
  for (const fs::path& hive_path : user_hives) {
    if (collected >= ctx.config.max_candidates_per_source) break;
    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
    try {
      values = local_parser.getKeyValues(hive, ctx.config.muicache_key);
    } catch (...) {
      continue;
    }

    for (const auto& value : values) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      std::string value_name = getLastPathComponent(value->getName(), '/');
      // Убираем суффиксы `.FriendlyAppName`, `.ApplicationCompany` (Windows 10+)
      for (const std::string_view suffix :
           {".FriendlyAppName", ".ApplicationCompany"}) {
        if (value_name.size() > suffix.size() &&
            toLowerAscii(value_name.substr(value_name.size() - suffix.size())) ==
                std::string(suffix)) {
          value_name = value_name.substr(0, value_name.size() - suffix.size());
          break;
        }
      }
      if (value_name.empty()) continue;

      auto executable = extractExecutableFromCommand(value_name);
      if (!executable.has_value()) continue;

      addExecutionEvidence(process_data, *executable, "MuiCache", "",
                          "user=" + username);
      collected++;
    }
  }

  logger->info("MuiCache: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
