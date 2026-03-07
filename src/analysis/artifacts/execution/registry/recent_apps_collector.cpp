/// @file recent_apps_collector.cpp
/// @brief Реализация RecentAppsCollector.
#include "recent_apps_collector.hpp"

#include <atomic>
#include <unordered_map>
#include <filesystem>
#include <future>
#include <string>

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
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;

void RecentAppsCollector::collect(const ExecutionEvidenceContext& ctx,
                                  std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_recent_apps) return;
  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  if (user_hives.empty()) return;

  struct RecentAppsBatchResult {
    std::unordered_map<std::string, ProcessInfo> process_data;
    std::size_t collected = 0;
  };

  std::atomic<std::size_t> global_collected{0};
  const auto process_hive =
      [&](RegistryAnalysis::IRegistryParser& parser, const fs::path& hive_path,
          RecentAppsBatchResult& result) {
        const std::string hive = hive_path.string();
        const std::string username = extractUsernameFromHivePath(hive_path);

        std::vector<std::string> app_subkeys;
        try {
          app_subkeys = parser.listSubkeys(hive, ctx.config.recent_apps_root_key);
        } catch (const std::exception& e) {
          logger->debug("RecentApps пропущен для {}: {}", hive, e.what());
          return;
        }

        for (const std::string& app_subkey : app_subkeys) {
          if (global_collected.load() >= ctx.config.max_candidates_per_source) break;

          const std::string app_key =
              ctx.config.recent_apps_root_key + "/" + app_subkey;
          std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
          try {
            values = parser.getKeyValues(hive, app_key);
          } catch (...) {
            continue;
          }

          std::vector<std::string> candidates;
          std::string timestamp;
          for (const auto& value : values) {
            const std::string value_name =
                getLastPathComponent(value->getName(), '/');
            const std::string value_name_lower = toLowerAscii(value_name);

            try {
              if (timestamp.empty() &&
                  (containsIgnoreCase(value_name_lower, "last") ||
                   containsIgnoreCase(value_name_lower, "time"))) {
                if (value->getType() ==
                    RegistryAnalysis::RegistryValueType::REG_QWORD) {
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

            if (value->getType() ==
                RegistryAnalysis::RegistryValueType::REG_BINARY) {
              auto binary_candidates = extractExecutableCandidatesFromBinary(
                  value->getAsBinary(), ctx.config.max_candidates_per_source);
              for (const auto& candidate : binary_candidates) {
                appendUniqueToken(candidates, candidate);
              }
            }
          }

          if (!ctx.config.recent_apps_recent_items_suffix.empty()) {
            const std::string recent_items_root =
                app_key + "/" + ctx.config.recent_apps_recent_items_suffix;
            std::vector<std::string> recent_item_subkeys;
            try {
              recent_item_subkeys =
                  parser.listSubkeys(hive, recent_items_root);
            } catch (...) {
              recent_item_subkeys.clear();
            }

            for (const std::string& recent_item : recent_item_subkeys) {
              if (global_collected.load() >= ctx.config.max_candidates_per_source) {
                break;
              }

              const std::string recent_item_key =
                  recent_items_root + "/" + recent_item;
              std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>
                  recent_item_values;
              try {
                recent_item_values = parser.getKeyValues(hive, recent_item_key);
              } catch (...) {
                continue;
              }

              std::vector<std::string> item_candidates;
              std::string item_timestamp = timestamp;

              if (auto executable = extractExecutableFromCommand(recent_item);
                  executable.has_value()) {
                appendUniqueToken(item_candidates, *executable);
              }

              for (const auto& item_value : recent_item_values) {
                const std::string item_value_name =
                    getLastPathComponent(item_value->getName(), '/');
                const std::string item_value_name_lower =
                    toLowerAscii(item_value_name);

                try {
                  if (item_timestamp.empty() &&
                      (containsIgnoreCase(item_value_name_lower, "last") ||
                       containsIgnoreCase(item_value_name_lower, "time"))) {
                    if (item_value->getType() ==
                        RegistryAnalysis::RegistryValueType::REG_QWORD) {
                      item_timestamp =
                          formatReasonableFiletime(item_value->getAsQword());
                    } else if (item_value->getType() ==
                                   RegistryAnalysis::RegistryValueType::REG_BINARY &&
                               item_value->getAsBinary().size() >= 8) {
                      item_timestamp = formatReasonableFiletime(
                          readLeUInt64(item_value->getAsBinary(), 0));
                    }
                  }
                } catch (...) {
                }

                if (auto executable = tryExtractExecutableFromDecoratedText(
                        item_value->getDataAsString());
                    executable.has_value()) {
                  appendUniqueToken(item_candidates, *executable);
                }
                if (auto executable = extractExecutableFromCommand(item_value_name);
                    executable.has_value()) {
                  appendUniqueToken(item_candidates, *executable);
                }

                if (item_value->getType() ==
                    RegistryAnalysis::RegistryValueType::REG_BINARY) {
                  auto binary_candidates = extractExecutableCandidatesFromBinary(
                      item_value->getAsBinary(), ctx.config.max_candidates_per_source);
                  for (const auto& candidate : binary_candidates) {
                    appendUniqueToken(item_candidates, candidate);
                  }
                }
              }

              for (const auto& executable : item_candidates) {
                const std::size_t ticket = global_collected.fetch_add(1);
                if (ticket >= ctx.config.max_candidates_per_source) {
                  global_collected.fetch_sub(1);
                  break;
                }

                addExecutionEvidence(result.process_data, executable, "RecentApps",
                                    item_timestamp,
                                    "user=" + username + ", app=" + app_subkey +
                                        ", recent_item=" + recent_item);
                result.collected++;
              }
            }
          }

          for (const auto& executable : candidates) {
            const std::size_t ticket = global_collected.fetch_add(1);
            if (ticket >= ctx.config.max_candidates_per_source) {
              global_collected.fetch_sub(1);
              break;
            }

            addExecutionEvidence(result.process_data, executable, "RecentApps",
                                timestamp,
                                "user=" + username + ", app=" + app_subkey);
            result.collected++;
          }
        }
      };

  const bool use_parallel = ctx.enable_parallel_user_hives &&
                            ctx.worker_threads > 1 && user_hives.size() > 1;
  std::size_t collected = 0;
  if (use_parallel) {
    logger->debug("Execution(RecentApps): параллельный режим (workers={})",
                  std::min<std::size_t>(ctx.worker_threads, user_hives.size()));
  }
  if (!use_parallel) {
    RecentAppsBatchResult sequential_result;
    RegistryAnalysis::RegistryParser local_parser;
    for (const auto& hive_path : user_hives) {
      process_hive(local_parser, hive_path, sequential_result);
      if (global_collected.load() >= ctx.config.max_candidates_per_source) break;
    }
    mergeProcessDataMaps(process_data, sequential_result.process_data);
    collected = sequential_result.collected;
  } else {
    const std::size_t workers =
        std::min<std::size_t>(ctx.worker_threads, user_hives.size());
    std::atomic<std::size_t> next_index{0};
    std::vector<std::future<RecentAppsBatchResult>> futures;
    futures.reserve(workers);

    for (std::size_t worker = 0; worker < workers; ++worker) {
      futures.push_back(std::async(std::launch::async, [&]() {
        RegistryAnalysis::RegistryParser local_parser;
        RecentAppsBatchResult worker_result;
        while (true) {
          const std::size_t index = next_index.fetch_add(1);
          if (index >= user_hives.size()) break;
          process_hive(local_parser, user_hives[index], worker_result);
          if (global_collected.load() >= ctx.config.max_candidates_per_source) {
            break;
          }
        }
        return worker_result;
      }));
    }

    for (auto& future : futures) {
      auto worker_result = future.get();
      mergeProcessDataMaps(process_data, worker_result.process_data);
      collected += worker_result.collected;
    }
  }

  logger->info("RecentApps: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
