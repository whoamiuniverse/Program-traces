/// @file feature_usage_collector.cpp
/// @brief Реализация FeatureUsageCollector.
#include "feature_usage_collector.hpp"

#include <atomic>
#include <future>
#include <unordered_map>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::readLeUInt64;

void FeatureUsageCollector::collect(const ExecutionEvidenceContext& ctx,
                                    std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_feature_usage) return;

  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  if (user_hives.empty()) return;

  struct FeatureUsageBatchResult {
    std::unordered_map<std::string, ProcessInfo> process_data;
    std::size_t collected = 0;
  };

  const std::vector<std::pair<std::string, std::string>> feature_keys = {
      {ctx.config.feature_usage_app_switched_key, "AppSwitched"},
      {ctx.config.feature_usage_show_jumpview_key, "ShowJumpView"},
      {ctx.config.feature_usage_app_badge_updated_key, "AppBadgeUpdated"}};

  std::atomic<std::size_t> global_collected{0};
  const auto process_hive =
      [&](RegistryAnalysis::IRegistryParser& parser, const fs::path& hive_path,
          FeatureUsageBatchResult& result) {
        const std::string hive = hive_path.string();
        const std::string username = extractUsernameFromHivePath(hive_path);

        for (const auto& [key_path, key_tag] : feature_keys) {
          if (key_path.empty()) continue;
          if (global_collected.load() >= ctx.config.max_candidates_per_source) break;

          std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
          try {
            values = parser.getKeyValues(hive, key_path);
          } catch (const std::exception& e) {
            logger->debug("FeatureUsage {} пропущен для {}: {}", key_tag, hive,
                          e.what());
            continue;
          }

          for (const auto& value : values) {
            if (global_collected.load() >= ctx.config.max_candidates_per_source) break;

            const std::string value_name =
                getLastPathComponent(value->getName(), '/');
            std::vector<std::string> candidates;

            if (auto executable = extractExecutableFromCommand(value_name);
                executable.has_value()) {
              appendUniqueToken(candidates, *executable);
            }

            if (auto executable =
                    tryExtractExecutableFromDecoratedText(value->getDataAsString());
                executable.has_value()) {
              appendUniqueToken(candidates, *executable);
            }

            std::string timestamp;
            try {
              if (value->getType() ==
                  RegistryAnalysis::RegistryValueType::REG_QWORD) {
                timestamp = formatReasonableFiletime(value->getAsQword());
              } else if (value->getType() ==
                         RegistryAnalysis::RegistryValueType::REG_BINARY) {
                const auto& binary = value->getAsBinary();
                if (binary.size() >= 8) {
                  timestamp = formatReasonableFiletime(readLeUInt64(binary, 0));
                  if (timestamp.empty() && binary.size() >= 16) {
                    timestamp = formatReasonableFiletime(
                        readLeUInt64(binary, binary.size() - 8));
                  }
                }

                const auto binary_candidates = extractExecutableCandidatesFromBinary(
                    binary, ctx.config.max_candidates_per_source);
                for (const auto& executable : binary_candidates) {
                  appendUniqueToken(candidates, executable);
                }
              }
            } catch (...) {
            }

            for (const auto& executable : candidates) {
              if (!isLikelyExecutionPath(executable)) continue;
              const std::size_t ticket = global_collected.fetch_add(1);
              if (ticket >= ctx.config.max_candidates_per_source) {
                global_collected.fetch_sub(1);
                break;
              }

              addExecutionEvidence(result.process_data, executable, "FeatureUsage",
                                  timestamp,
                                  "user=" + username + ", key=" + key_tag +
                                      ", value=" + value_name);
              result.collected++;
            }
          }
        }
      };

  const bool use_parallel = ctx.enable_parallel_user_hives &&
                            ctx.worker_threads > 1 && user_hives.size() > 1;
  std::size_t collected = 0;
  if (use_parallel) {
    logger->debug("Execution(FeatureUsage): параллельный режим (workers={})",
                  std::min<std::size_t>(ctx.worker_threads, user_hives.size()));
  }
  if (!use_parallel) {
    FeatureUsageBatchResult sequential_result;
    RegistryAnalysis::RegistryParser local_parser;
    for (const auto& hive_path : user_hives) {
      process_hive(local_parser, hive_path, sequential_result);
      if (global_collected.load() >= ctx.config.max_candidates_per_source) break;
    }
    mergeProcessDataMaps(process_data, std::move(sequential_result.process_data));
    collected = sequential_result.collected;
  } else {
    const std::size_t workers =
        std::min<std::size_t>(ctx.worker_threads, user_hives.size());
    std::atomic<std::size_t> next_index{0};
    std::vector<std::future<FeatureUsageBatchResult>> futures;
    futures.reserve(workers);

    for (std::size_t worker = 0; worker < workers; ++worker) {
      futures.push_back(std::async(std::launch::async, [&]() {
        RegistryAnalysis::RegistryParser local_parser;
        FeatureUsageBatchResult worker_result;
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
      mergeProcessDataMaps(process_data, std::move(worker_result.process_data));
      collected += worker_result.collected;
    }
  }

  logger->info("FeatureUsage: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
