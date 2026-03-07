/// @file timeline_collector.cpp
/// @brief Реализация TimelineCollector.
#include "timeline_collector.hpp"

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

void TimelineCollector::collect(const ExecutionEvidenceContext& ctx,
                                std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_timeline) return;
  const auto logger = GlobalLogger::get();
  std::size_t collected = 0;
  std::error_code ec;
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 16 * 1024 * 1024);

  for (const fs::path& users_root :
       {fs::path(ctx.disk_root) / "Users",
        fs::path(ctx.disk_root) / "Documents and Settings"}) {
    ec.clear();
    if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
        ec) {
      continue;
    }

    for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
      if (ec || collected >= ctx.config.max_candidates_per_source) break;
      if (!user_entry.is_directory()) continue;

      const std::string username = user_entry.path().filename().string();
      const fs::path timeline_root =
          user_entry.path() / ctx.config.timeline_root_suffix;
      const auto resolved_root = findPathCaseInsensitive(timeline_root);
      if (!resolved_root.has_value()) continue;

      fs::recursive_directory_iterator iterator(*resolved_root, ec);
      fs::recursive_directory_iterator end;
      for (; iterator != end && !ec; iterator.increment(ec)) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        if (!iterator->is_regular_file(ec)) continue;

        const std::string filename_lower =
            toLowerAscii(iterator->path().filename().string());
        const std::string ext_lower =
            toLowerAscii(iterator->path().extension().string());
        if (ext_lower != ".db" ||
            (filename_lower.find("activitiescache") == std::string::npos &&
             filename_lower.find("activitycache") == std::string::npos)) {
          continue;
        }

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
            "timeline=" +
            makeRelativePathForDetails(*resolved_root, iterator->path()) +
            ", user=" + username;
        for (const auto& executable : candidates) {
          if (collected >= ctx.config.max_candidates_per_source) break;
          if (!isLikelyExecutionPath(executable)) continue;
          addExecutionEvidence(process_data, executable, "Timeline", timestamp,
                              details);
          collected++;
        }
      }
    }
  }

  logger->info("Timeline: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
