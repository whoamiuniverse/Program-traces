/// @file shimcache_collector.cpp
/// @brief Реализация ShimCacheCollector.
#include "shimcache_collector.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "analysis/artifacts/execution/registry/shimcache_decoder.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::extractExecutableCandidatesFromStrings;
using EvidenceUtils::toLowerAscii;

void ShimCacheCollector::collect(
    const ExecutionEvidenceContext& ctx,
    std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_shimcache) return;
  if (ctx.system_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::string& system_hive_path = ctx.system_hive_path;
  try {
    std::string shimcache_value_path = ctx.config.shimcache_value_path;
    const std::string control_set_root =
        resolveControlSetRoot(local_parser, system_hive_path, "CurrentControlSet");
    const std::string marker = "CurrentControlSet/";
    std::vector<std::string> value_paths = {shimcache_value_path};

    if (shimcache_value_path.rfind(marker, 0) == 0) {
      const std::string suffix = shimcache_value_path.substr(marker.size());
      if (!control_set_root.empty()) {
        value_paths.push_back(control_set_root + "/" + suffix);
      }
      for (int index = 1; index <= 5; ++index) {
        std::ostringstream stream;
        stream << "ControlSet" << std::setw(3) << std::setfill('0') << index
               << "/" << suffix;
        value_paths.push_back(stream.str());
      }
    }

    std::optional<std::string> last_error;
    std::unique_ptr<RegistryAnalysis::IRegistryData> value;
    for (const auto& candidate_path : value_paths) {
      try {
        value = local_parser.getSpecificValue(system_hive_path, candidate_path);
        if (value) break;
      } catch (const std::exception& e) {
        last_error = e.what();
      }
    }

    if (!value) {
      if (last_error.has_value()) {
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "ShimCache недоступен: {}", *last_error);
      }
      return;
    }

    std::size_t structured_count = 0;
    std::size_t fallback_count = 0;
    std::unordered_set<std::string> seen;

    auto append_unique = [&](const std::string& path, const std::string& timestamp,
                             const std::string& details) {
      const std::string key = toLowerAscii(path);
      if (!seen.insert(key).second) return;
      addExecutionEvidence(process_data, path, "ShimCache", timestamp, details);
    };

    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
      const auto binary = value->getAsBinary();
      const auto decoded_records =
          parseShimCacheRecords(binary, ctx.config.max_candidates_per_source);

      for (const auto& record : decoded_records) {
        append_unique(record.executable_path, record.timestamp, record.details);
        if (record.no_exec_flag) {
          auto& info = ensureProcessInfo(process_data, record.executable_path);
          appendTamperFlag(info.tamper_flags, "shimcache_no_exec_flag");
        }
      }
      structured_count = decoded_records.size();

      if (decoded_records.empty()) {
        const auto structured_candidates = parseShimCacheStructuredCandidates(
            binary, ctx.config.max_candidates_per_source);
        for (const auto& candidate : structured_candidates) {
          append_unique(candidate.executable_path, candidate.timestamp,
                        candidate.details);
        }
        structured_count = structured_candidates.size();
      }

      if (structured_count == 0) {
        const auto fallback_candidates = extractExecutableCandidatesFromBinary(
            binary, ctx.config.max_candidates_per_source);
        for (const auto& path : fallback_candidates) {
          append_unique(path, "", "AppCompatCache(binary-fallback)");
        }
        fallback_count = fallback_candidates.size();
      }
    } else {
      const auto candidates = extractExecutableCandidatesFromStrings(
          {value->getDataAsString()}, ctx.config.max_candidates_per_source);
      for (const auto& path : candidates) {
        append_unique(path, "", "AppCompatCache(string)");
      }
      fallback_count = candidates.size();
    }

    logger->info("ShimCache: structured={} fallback={} total={}",
                 structured_count, fallback_count, seen.size());
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка ShimCache: {}", e.what());
  }
}

}  // namespace WindowsDiskAnalysis
