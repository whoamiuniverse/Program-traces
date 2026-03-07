/// @file bits_queue_collector.cpp
/// @brief Реализация BitsQueueCollector.
#include "bits_queue_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <sstream>
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

void BitsQueueCollector::collect(const ExecutionEvidenceContext& ctx,
                                 std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_bits) return;
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 16 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path bits_root = fs::path(ctx.disk_root) / ctx.config.bits_downloader_path;
  const auto resolved_root = findPathCaseInsensitive(bits_root);
  if (!resolved_root.has_value()) {
    logger->info("BITS: добавлено 0 кандидат(ов)");
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
    const bool is_qmgr = filename_lower.rfind("qmgr", 0) == 0;
    const bool looks_like_db = ext_lower == ".dat" || ext_lower == ".db";
    if (!is_qmgr || !looks_like_db) continue;

    const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
    if (!data_opt.has_value()) continue;

    const std::vector<std::string> readable = collectReadableStrings(*data_opt, 6);

    std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
        *data_opt, ctx.config.max_candidates_per_source);
    if (candidates.empty()) {
      for (const auto& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
    }

    std::vector<std::string> owner_sids;
    std::vector<std::string> job_context;
    for (const std::string& line : readable) {
      const auto sid_candidates = extractSidCandidatesFromLine(line);
      for (const std::string& sid : sid_candidates) {
        appendUniqueToken(owner_sids, sid);
      }

      std::string normalized = trim_copy(line);
      if (normalized.empty() || normalized.size() > 200) continue;
      const std::string lowered = toLowerAscii(normalized);
      if (lowered.find("displayname=") == 0 || lowered.find("jobname=") == 0 ||
          lowered.find("description=") == 0 || lowered.find("owner=") == 0 ||
          lowered.find("notifycmdline=") == 0 ||
          lowered.find("http://") != std::string::npos ||
          lowered.find("https://") != std::string::npos) {
        appendUniqueToken(job_context, std::move(normalized));
      }
    }

    const std::string timestamp =
        fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));

    std::ostringstream details_stream;
    details_stream << "bits="
                   << makeRelativePathForDetails(*resolved_root, iterator->path());
    if (!owner_sids.empty()) {
      details_stream << ", sid=" << owner_sids.front();
      details_stream << ", owner_sids=";
      for (std::size_t index = 0; index < owner_sids.size(); ++index) {
        if (index > 0) details_stream << "|";
        details_stream << owner_sids[index];
      }
    }
    if (!job_context.empty()) {
      details_stream << ", job_context=";
      for (std::size_t index = 0; index < job_context.size(); ++index) {
        if (index > 0) details_stream << " || ";
        details_stream << job_context[index];
        if (index >= 4) break;
      }
    }
    const std::string details = details_stream.str();

    for (const auto& executable : candidates) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      if (!isLikelyExecutionPath(executable)) continue;
      addExecutionEvidence(process_data, executable, "BITS", timestamp, details);
      collected++;
    }
  }

  logger->info("BITS: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
