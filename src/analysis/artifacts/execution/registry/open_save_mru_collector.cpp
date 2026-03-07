/// @file open_save_mru_collector.cpp
/// @brief Реализация OpenSaveMruCollector.
#include "open_save_mru_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::toLowerAscii;

void OpenSaveMruCollector::collect(const ExecutionEvidenceContext& ctx,
                                   std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_open_save_mru) return;
  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  if (user_hives.empty()) return;

  std::size_t collected = 0;
  for (const fs::path& hive_path : user_hives) {
    if (collected >= ctx.config.max_candidates_per_source) break;
    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    std::vector<std::string> ext_subkeys;
    try {
      ext_subkeys = local_parser.listSubkeys(hive, ctx.config.open_save_mru_key);
    } catch (...) {
      continue;
    }

    for (const std::string& ext : ext_subkeys) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      const std::string ext_key = ctx.config.open_save_mru_key + "/" + ext;

      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = local_parser.getKeyValues(hive, ext_key);
      } catch (...) {
        continue;
      }

      for (const auto& value : values) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        const std::string value_name = getLastPathComponent(value->getName(), '/');
        const std::string name_lower = toLowerAscii(value_name);
        if (name_lower == "mrulistex" || name_lower == "mrulist") continue;

        if (value->getType() != RegistryAnalysis::RegistryValueType::REG_BINARY) {
          continue;
        }
        const auto& binary = value->getAsBinary();
        if (binary.empty()) continue;

        // Извлекаем строки из PIDL бинарных данных
        const auto strings = collectReadableStrings(binary, 5);
        for (const auto& candidate : strings) {
          if (collected >= ctx.config.max_candidates_per_source) break;
          auto executable = extractExecutableFromCommand(candidate);
          if (!executable.has_value()) continue;

          addExecutionEvidence(process_data, *executable, "OpenSaveMRU", "",
                              "user=" + username + ", ext=" + ext);
          collected++;
        }
      }
    }
  }

  logger->info("OpenSaveMRU: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
