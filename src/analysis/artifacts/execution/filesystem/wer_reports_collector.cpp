/// @file wer_reports_collector.cpp
/// @brief Реализация WerReportsCollector.
#include "wer_reports_collector.hpp"

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

void WerReportsCollector::collect(const ExecutionEvidenceContext& ctx,
                                  std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_wer) return;
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 2 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  auto scan_wer_directory = [&](const fs::path& root_path) {
    if (collected >= ctx.config.max_candidates_per_source) return;
    const auto resolved = findPathCaseInsensitive(root_path);
    if (!resolved.has_value()) return;

    fs::recursive_directory_iterator iterator(*resolved, ec);
    fs::recursive_directory_iterator end;
    for (; iterator != end && !ec; iterator.increment(ec)) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      if (!iterator->is_regular_file(ec)) continue;
      if (toLowerAscii(iterator->path().extension().string()) != ".wer") continue;

      const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
      if (!data_opt.has_value()) continue;

      std::vector<std::string> candidates;
      const std::vector<std::string> readable = collectReadableStrings(*data_opt, 4);
      for (std::string line : readable) {
        trim(line);
        if (line.empty()) continue;
        std::string lowered = toLowerAscii(line);
        for (const std::string prefix : {"apppath=", "applicationpath=",
                                         "commandline=", "path="}) {
          if (lowered.rfind(prefix, 0) == 0 && line.size() > prefix.size()) {
            line = line.substr(prefix.size());
            trim(line);
            break;
          }
        }
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
      if (candidates.empty()) {
        candidates = extractExecutableCandidatesFromBinary(
            *data_opt, ctx.config.max_candidates_per_source);
      }

      const std::string timestamp =
          fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
      const std::string details =
          "wer=" + makeRelativePathForDetails(*resolved, iterator->path());
      for (const auto& executable : candidates) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "WER", timestamp, details);
        collected++;
      }
    }
  };

  scan_wer_directory(fs::path(ctx.disk_root) / ctx.config.wer_programdata_path);

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
      scan_wer_directory(user_entry.path() / ctx.config.wer_user_suffix);
    }
  }

  logger->info("WER: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
