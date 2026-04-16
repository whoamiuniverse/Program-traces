/// @file lnk_recent_collector.cpp
/// @brief Реализация LnkRecentCollector.
#include "lnk_recent_collector.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <unordered_map>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/lnk/lnk_parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::toLowerAscii;

void LnkRecentCollector::collect(const ExecutionEvidenceContext& ctx,
                                 std::unordered_map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(ctx.config.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path users_root = fs::path(ctx.disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;

    const fs::path recent_dir = user_entry.path() / ctx.config.recent_lnk_suffix;
    ec.clear();
    if (!fs::exists(recent_dir, ec) || ec || !fs::is_directory(recent_dir, ec) ||
        ec) {
      continue;
    }

    for (const auto& file_entry : fs::directory_iterator(recent_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;
      if (toLowerAscii(file_entry.path().extension().string()) != ".lnk") continue;

      std::vector<std::string> candidates;
      std::string timestamp;
      std::string details = "lnk=" + file_entry.path().filename().string();
      auto appendCandidate = [&](std::string candidate) {
        trim(candidate);
        if (candidate.empty()) return;
        auto appendUnique = [&](std::string value) {
          if (std::ranges::find(candidates, value) == candidates.end()) {
            candidates.push_back(std::move(value));
          }
        };

        if (auto executable = extractExecutableFromCommand(candidate);
            executable.has_value()) {
          appendUnique(*executable);
          return;
        }
        if (isLikelyExecutionPath(candidate, true)) {
          appendUnique(std::move(candidate));
        }
      };

      if (auto parsed = parseLnkFile(file_entry.path().string());
          parsed.has_value()) {
        if (!parsed->target_path.empty()) {
          appendCandidate(parsed->target_path);
        } else if (!parsed->relative_path.empty()) {
          appendCandidate(parsed->relative_path);
        }

        if (!parsed->write_time.empty() && parsed->write_time != "N/A") {
          timestamp = parsed->write_time;
        }
        if (!parsed->relative_path.empty()) {
          details += ", relative=" + parsed->relative_path;
        }
        if (!parsed->working_dir.empty()) {
          details += ", cwd=" + parsed->working_dir;
        }
      }

      if (candidates.empty()) {
        collectFileCandidates(file_entry.path(), max_bytes,
                              ctx.config.max_candidates_per_source, candidates);
        if (candidates.empty()) {
          if (auto fallback = extractExecutableFromCommand(
                  file_entry.path().filename().string());
              fallback.has_value()) {
            candidates.push_back(*fallback);
          }
        }
      }

      if (timestamp.empty()) {
        timestamp =
            fileTimeToUtcString(fs::last_write_time(file_entry.path(), ec));
      }

      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "LNKRecent", timestamp,
                            details);
        collected++;
      }
    }
  }

  logger->info("LNK Recent: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
