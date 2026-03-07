/// @file typed_paths_collector.cpp
/// @brief Реализация TypedPathsCollector.
#include "typed_paths_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>

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

void TypedPathsCollector::collect(const ExecutionEvidenceContext& ctx,
                                  std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_typed_paths) return;
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
      values = local_parser.getKeyValues(hive, ctx.config.typed_paths_key);
    } catch (...) {
      continue;
    }

    for (const auto& value : values) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      const std::string value_name = getLastPathComponent(value->getName(), '/');
      if (value_name.empty() || toLowerAscii(value_name) == "mrulist") continue;

      const std::string typed_path = value->getDataAsString();
      if (typed_path.empty()) continue;

      auto executable = extractExecutableFromCommand(typed_path);
      if (!executable.has_value()) continue;

      addExecutionEvidence(process_data, *executable, "TypedPaths", "",
                          "user=" + username + ", typed=" + typed_path);
      collected++;
    }
  }

  logger->info("TypedPaths: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
