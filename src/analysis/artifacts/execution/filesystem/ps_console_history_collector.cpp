/// @file ps_console_history_collector.cpp
/// @brief Реализация PsConsoleHistoryCollector.
#include "ps_console_history_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <fstream>
#include <string>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;

void PsConsoleHistoryCollector::collect(const ExecutionEvidenceContext& ctx,
                                        std::unordered_map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  std::size_t collected = 0;
  std::error_code ec;

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
      const fs::path history_path =
          user_entry.path() / ctx.config.ps_history_suffix;
      const auto resolved = findPathCaseInsensitive(history_path);
      if (!resolved.has_value()) continue;

      std::ifstream file(resolved->string());
      if (!file.is_open()) continue;

      std::string line;
      while (std::getline(file, line) &&
             collected < ctx.config.max_candidates_per_source) {
        trim(line);
        if (line.empty() || line.front() == '#') continue;

        auto executable = extractExecutableFromCommand(line);
        if (!executable.has_value()) continue;

        addExecutionEvidence(process_data, *executable, "PSConsoleHistory", "",
                            "user=" + username);
        collected++;
      }
    }
  }

  logger->info("PSConsoleHistory: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
