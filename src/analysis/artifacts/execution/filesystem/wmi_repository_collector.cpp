/// @file wmi_repository_collector.cpp
/// @brief Реализация WmiRepositoryCollector.
#include "wmi_repository_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;

void WmiRepositoryCollector::collect(const ExecutionEvidenceContext& ctx,
                                     std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_wmi_repository) return;
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 16 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path repository_root =
      fs::path(ctx.disk_root) / ctx.config.wmi_repository_path;
  const auto resolved_root = findPathCaseInsensitive(repository_root);
  if (!resolved_root.has_value()) {
    logger->info("WMIRepository: добавлено 0 кандидат(ов)");
    return;
  }

  fs::recursive_directory_iterator iterator(*resolved_root, ec);
  fs::recursive_directory_iterator end;
  for (; iterator != end && !ec; iterator.increment(ec)) {
    if (collected >= ctx.config.max_candidates_per_source) break;
    if (!iterator->is_regular_file(ec)) continue;

    const std::string filename_lower =
        toLowerAscii(iterator->path().filename().string());
    const std::string ext_lower = toLowerAscii(iterator->path().extension().string());
    const bool is_target = filename_lower == "objects.data" ||
                           ext_lower == ".map" || ext_lower == ".btr";
    if (!is_target) continue;

    const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
    if (!data_opt.has_value()) continue;

    std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
        *data_opt, ctx.config.max_candidates_per_source);
    if (candidates.empty()) {
      const auto readable = collectReadableStrings(*data_opt, 6);
      for (const auto& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
    }

    const std::string timestamp =
        fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
    const std::string details =
        "wmi=" + makeRelativePathForDetails(*resolved_root, iterator->path());
    for (const auto& executable : candidates) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      if (!isLikelyExecutionPath(executable)) continue;
      addExecutionEvidence(process_data, executable, "WMIRepository", timestamp,
                          details);
      collected++;
    }
  }

  logger->info("WMIRepository: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
