/// @file bam_dam_collector.cpp
/// @brief Реализация BamDamCollector.
#include "bam_dam_collector.hpp"

#include <unordered_set>
#include <unordered_map>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;

void BamDamCollector::collect(const ExecutionEvidenceContext& ctx,
                              std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (ctx.system_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::string& system_hive_path = ctx.system_hive_path;
  std::unordered_set<std::string> seen;
  auto collect_root = [&](const std::string& root_path, const std::string& source) {
    if (root_path.empty()) return static_cast<std::size_t>(0);

    const std::string control_set_root =
        resolveControlSetRoot(local_parser, system_hive_path, "CurrentControlSet");
    if (control_set_root.empty()) return static_cast<std::size_t>(0);

    std::string normalized_root = root_path;
    const std::string marker = "CurrentControlSet/";
    if (normalized_root.rfind(marker, 0) == 0) {
      normalized_root.replace(0, marker.size(), control_set_root + "/");
    }

    std::vector<std::string> sid_subkeys;
    try {
      sid_subkeys = local_parser.listSubkeys(system_hive_path, normalized_root);
    } catch (const std::exception&) {
      return static_cast<std::size_t>(0);
    }

    std::size_t collected = 0;
    for (const std::string& sid : sid_subkeys) {
      const std::string sid_key = normalized_root + "/" + sid;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
        try {
          values = local_parser.getKeyValues(system_hive_path, sid_key);
        } catch (...) {
          continue;
        }

      for (const auto& value : values) {
        std::string executable =
            getLastPathComponent(value->getName(), '/');
        if (auto parsed = extractExecutableFromCommand(executable);
            parsed.has_value()) {
          executable = *parsed;
        } else {
          continue;
        }

        std::string timestamp;
        try {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
            const auto& binary = value->getAsBinary();
            const uint64_t filetime = readLeUInt64(binary, 0);
            if (filetime >= kFiletimeUnixEpoch && filetime <= kMaxReasonableFiletime) {
              timestamp = filetimeToString(filetime);
            }
          }
        } catch (...) {
        }

        const std::string dedupe_key =
            toLowerAscii(source + "|" + sid + "|" + executable);
        if (!seen.insert(dedupe_key).second) continue;

        addExecutionEvidence(process_data, executable, source, timestamp,
                            source + " SID=" + sid);
        collected++;
      }
    }
    return collected;
  };

  const std::size_t bam_collected =
      collect_root(ctx.config.bam_root_path, "BAM") +
      collect_root(ctx.config.bam_legacy_root_path, "BAM");
  const std::size_t dam_collected =
      collect_root(ctx.config.dam_root_path, "DAM") +
      collect_root(ctx.config.dam_legacy_root_path, "DAM");

  logger->info("BAM: добавлено {} кандидат(ов)", bam_collected);
  logger->info("DAM: добавлено {} кандидат(ов)", dam_collected);
}

}  // namespace WindowsDiskAnalysis
