/// @file last_visited_mru_collector.cpp
/// @brief Реализация LastVisitedMruCollector.
#include "last_visited_mru_collector.hpp"

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

void LastVisitedMruCollector::collect(const ExecutionEvidenceContext& ctx,
                                      std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_last_visited_mru) return;
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
      values = local_parser.getKeyValues(hive, ctx.config.last_visited_mru_key);
    } catch (...) {
      continue;
    }

    for (const auto& value : values) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      const std::string value_name = getLastPathComponent(value->getName(), '/');
      const std::string name_lower = toLowerAscii(value_name);
      // MRUListEx / MRUList хранят упорядочивание, пропускаем
      if (name_lower == "mrulistex" || name_lower == "mrulist") continue;

      // Значение: UTF-16LE путь приложения + null-терминатор + PIDL данные
      if (value->getType() != RegistryAnalysis::RegistryValueType::REG_BINARY) {
        continue;
      }
      const auto& binary = value->getAsBinary();
      if (binary.size() < 4) continue;

      // Декодируем ведущий UTF-16LE путь приложения
      auto decoded = decodeUtf16PathFromBytes(binary, 0, binary.size());
      if (!decoded.has_value()) continue;

      auto executable = extractExecutableFromCommand(*decoded);
      if (!executable.has_value()) continue;

      addExecutionEvidence(process_data, *executable, "LastVisitedMRU", "",
                          "user=" + username);
      collected++;
    }
  }

  logger->info("LastVisitedMRU: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
