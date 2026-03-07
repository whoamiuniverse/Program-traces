/// @file jump_lists_collector.cpp
/// @brief Реализация JumpListsCollector.
#include "jump_lists_collector.hpp"

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
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::toLowerAscii;

void JumpListsCollector::collect(const ExecutionEvidenceContext& ctx,
                                 std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_jump_lists) return;
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(ctx.config.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  auto process_jump_dir = [&](const fs::path& jump_dir) {
    ec.clear();
    if (!fs::exists(jump_dir, ec) || ec || !fs::is_directory(jump_dir, ec) || ec) {
      return;
    }

    for (const auto& file_entry : fs::directory_iterator(jump_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;

      const std::string ext = toLowerAscii(file_entry.path().extension().string());
      if (ext != ".automaticdestinations-ms" && ext != ".customdestinations-ms") {
        continue;
      }

      std::vector<std::string> candidates;
      collectFileCandidates(file_entry.path(), max_bytes,
                            ctx.config.max_candidates_per_source, candidates);

      const std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      const std::string details = "jump=" + file_entry.path().filename().string();
      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "JumpList", timestamp,
                            details);
        collected++;
      }
    }
  };

  const fs::path users_root = fs::path(ctx.disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;
    process_jump_dir(user_entry.path() / ctx.config.jump_auto_suffix);
    process_jump_dir(user_entry.path() / ctx.config.jump_custom_suffix);
  }

  logger->info("Jump Lists: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
