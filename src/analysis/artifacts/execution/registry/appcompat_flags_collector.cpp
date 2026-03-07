/// @file appcompat_flags_collector.cpp
/// @brief Реализация AppCompatFlagsCollector.
#include "appcompat_flags_collector.hpp"

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

void AppCompatFlagsCollector::collect(const ExecutionEvidenceContext& ctx,
                                      std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_appcompat_flags) return;
  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  std::size_t collected = 0;

  // Системный контекст: SOFTWARE hive
  if (!ctx.software_hive_path.empty()) {
    for (const std::string& key :
         {ctx.config.appcompat_layers_key, ctx.config.appcompat_assist_key}) {
      if (key.empty() || collected >= ctx.config.max_candidates_per_source) break;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = local_parser.getKeyValues(ctx.software_hive_path, key);
      } catch (...) {
        continue;
      }
      for (const auto& value : values) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        const std::string value_name = getLastPathComponent(value->getName(), '/');
        auto executable = extractExecutableFromCommand(value_name);
        if (!executable.has_value()) continue;

        const std::string flags = value->getDataAsString();
        addExecutionEvidence(process_data, *executable, "AppCompatFlags", "",
                            "scope=system, key=" + getLastPathComponent(key, '/') +
                                (flags.empty() ? "" : ", flags=" + flags));
        collected++;
      }
    }
  }

  // Пользовательский контекст: NTUSER.DAT
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  for (const fs::path& hive_path : user_hives) {
    if (collected >= ctx.config.max_candidates_per_source) break;
    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    for (const std::string& key :
         {ctx.config.appcompat_layers_key, ctx.config.appcompat_assist_key}) {
      if (key.empty() || collected >= ctx.config.max_candidates_per_source) break;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = local_parser.getKeyValues(hive, key);
      } catch (...) {
        continue;
      }
      for (const auto& value : values) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        const std::string value_name = getLastPathComponent(value->getName(), '/');
        auto executable = extractExecutableFromCommand(value_name);
        if (!executable.has_value()) continue;

        const std::string flags = value->getDataAsString();
        addExecutionEvidence(process_data, *executable, "AppCompatFlags", "",
                            "scope=user, user=" + username +
                                ", key=" + getLastPathComponent(key, '/') +
                                (flags.empty() ? "" : ", flags=" + flags));
        collected++;
      }
    }
  }

  logger->info("AppCompatFlags: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
