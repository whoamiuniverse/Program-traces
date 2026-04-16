/// @file task_scheduler_collector.cpp
/// @brief Реализация TaskSchedulerCollector.
#include "task_scheduler_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <string>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;

void TaskSchedulerCollector::collect(const ExecutionEvidenceContext& ctx,
                                     std::unordered_map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(ctx.config.binary_scan_max_mb), 4 * 1024 * 1024);
  std::size_t collected = 0;
  std::unordered_set<std::string> parsed_task_ids;

  const fs::path task_root = fs::path(ctx.disk_root) / ctx.config.task_scheduler_root_path;
  if (const auto resolved_tasks_root = findPathCaseInsensitive(task_root);
      resolved_tasks_root.has_value()) {
    std::error_code ec;
    fs::recursive_directory_iterator iterator(*resolved_tasks_root, ec);
    fs::recursive_directory_iterator end;
    for (; iterator != end && !ec; iterator.increment(ec)) {
      if (collected >= ctx.config.max_candidates_per_source) break;
      if (!iterator->is_regular_file(ec)) continue;

      const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
      if (!data_opt.has_value()) continue;

      std::vector<std::string> text_candidates;
      const std::vector<std::string> readable =
          collectReadableStrings(*data_opt, 4);
      for (const std::string& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(text_candidates, *executable);
        }
      }
      if (text_candidates.empty()) {
        text_candidates = extractExecutableCandidatesFromBinary(
            *data_opt, ctx.config.max_candidates_per_source);
      }

      const std::string timestamp =
          fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
      const std::string details =
          "task=" + makeRelativePathForDetails(*resolved_tasks_root, iterator->path());
      for (const auto& executable : text_candidates) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "TaskScheduler", timestamp,
                            details);
        collected++;
      }
    }
  }

  if (!ctx.software_hive_path.empty() && collected < ctx.config.max_candidates_per_source) {
    auto collect_task_cache_task = [&](const std::string& task_id,
                                       const std::string& details_prefix) {
      if (task_id.empty() || collected >= ctx.config.max_candidates_per_source) return;

      const std::string task_id_lower = toLowerAscii(task_id);
      if (!parsed_task_ids.insert(task_id_lower).second) return;

      const std::string task_key = ctx.config.task_cache_tasks_key + "/" + task_id;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = local_parser.getKeyValues(ctx.software_hive_path, task_key);
      } catch (...) {
        return;
      }

      std::string timestamp;
      std::vector<std::string> candidates;
      for (const auto& value : values) {
        try {
          const std::string value_name =
              toLowerAscii(getLastPathComponent(value->getName(), '/'));
          if (timestamp.empty() &&
              (containsIgnoreCase(value_name, "time") ||
               containsIgnoreCase(value_name, "date"))) {
            if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
              timestamp = formatReasonableFiletime(value->getAsQword());
            } else if (value->getType() ==
                           RegistryAnalysis::RegistryValueType::REG_BINARY &&
                       value->getAsBinary().size() >= 8) {
              timestamp = formatReasonableFiletime(
                  readLeUInt64(value->getAsBinary(), 0));
            }
          }
        } catch (...) {
        }

        if (auto executable =
                tryExtractExecutableFromDecoratedText(value->getDataAsString());
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }

        if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
          const auto binary_candidates = extractExecutableCandidatesFromBinary(
              value->getAsBinary(), ctx.config.max_candidates_per_source);
          for (const auto& executable : binary_candidates) {
            appendUniqueToken(candidates, executable);
          }
        }
      }

      for (const auto& executable : candidates) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "TaskScheduler", timestamp,
                            details_prefix + task_id);
        collected++;
      }
    };

    try {
      const auto task_ids =
          local_parser.listSubkeys(ctx.software_hive_path, ctx.config.task_cache_tasks_key);
      for (const auto& task_id : task_ids) {
        if (collected >= ctx.config.max_candidates_per_source) break;
        collect_task_cache_task(task_id, "taskcache=");
      }
    } catch (const std::exception& e) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "TaskScheduler(TaskCache) пропущен: {}", e.what());
    }

    if (!ctx.config.task_cache_tree_key.empty() &&
        collected < ctx.config.max_candidates_per_source) {
      std::vector<std::string> pending_tree_keys = {ctx.config.task_cache_tree_key};
      std::unordered_set<std::string> visited_tree_keys;

      while (!pending_tree_keys.empty() &&
             collected < ctx.config.max_candidates_per_source) {
        std::string tree_key = pending_tree_keys.back();
        pending_tree_keys.pop_back();

        const std::string tree_key_lower = toLowerAscii(tree_key);
        if (!visited_tree_keys.insert(tree_key_lower).second) continue;

        std::vector<std::string> child_subkeys;
        try {
          child_subkeys = local_parser.listSubkeys(ctx.software_hive_path, tree_key);
        } catch (...) {
          child_subkeys.clear();
        }
        for (const std::string& child : child_subkeys) {
          pending_tree_keys.push_back(tree_key + "/" + child);
        }

        std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
        try {
          values = local_parser.getKeyValues(ctx.software_hive_path, tree_key);
        } catch (...) {
          continue;
        }

        std::string task_id;
        for (const auto& value : values) {
          const std::string value_name =
              toLowerAscii(getLastPathComponent(value->getName(), '/'));
          if (value_name == "id") {
            task_id = trim_copy(value->getDataAsString());
            break;
          }
        }

        if (!task_id.empty()) {
          collect_task_cache_task(task_id, "taskcache_tree=" + tree_key + ", id=");
        }
      }
    }
  }

  logger->info("TaskScheduler: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
