/// @file user_assist_runmru_collector.cpp
/// @brief Реализация UserAssistRunMruCollector.
#include "user_assist_runmru_collector.hpp"

#include <atomic>
#include <future>
#include <unordered_map>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::readLeUInt32;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;

void UserAssistRunMruCollector::collect(const ExecutionEvidenceContext& ctx,
                                        std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_userassist && !ctx.config.enable_runmru) return;

  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(ctx.disk_root);
  if (user_hives.empty()) return;

  struct HiveBatchResult {
    std::unordered_map<std::string, ProcessInfo> process_data;
    std::size_t userassist_count = 0;
    std::size_t runmru_count = 0;
  };

  const auto process_hive =
      [&](RegistryAnalysis::IRegistryParser& parser, const fs::path& hive_path,
          HiveBatchResult& result) {
        const std::string hive = hive_path.string();
        const std::string username = extractUsernameFromHivePath(hive_path);

        if (ctx.config.enable_userassist) {
          try {
            const auto guid_subkeys =
                parser.listSubkeys(hive, ctx.config.userassist_key);
            for (const std::string& guid : guid_subkeys) {
              const std::string count_key =
                  ctx.config.userassist_key + "/" + guid + "/Count";
              std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
              try {
                values = parser.getKeyValues(hive, count_key);
              } catch (...) {
                continue;
              }

              for (const auto& value : values) {
                std::string encoded_name =
                    getLastPathComponent(value->getName(), '/');
                if (encoded_name.empty()) continue;

                std::string decoded_name = decodeRot13(encoded_name);
                decoded_name = replace_all(decoded_name, "UEME_RUNPATH:", "");
                decoded_name = replace_all(decoded_name, "UEME_RUNPIDL:", "");
                trim(decoded_name);

                auto executable = extractExecutableFromCommand(decoded_name);
                if (!executable.has_value()) continue;

                uint32_t run_count = 0;
                std::string timestamp;
                if (value->getType() ==
                    RegistryAnalysis::RegistryValueType::REG_BINARY) {
                  const auto& binary = value->getAsBinary();
                  if (binary.size() >= 8) {
                    run_count = readLeUInt32(binary, 4);
                  }
                  if (binary.size() >= 68) {
                    const uint64_t filetime = readLeUInt64(binary, 60);
                    if (filetime >= kFiletimeUnixEpoch &&
                        filetime <= kMaxReasonableFiletime) {
                      timestamp = filetimeToString(filetime);
                    }
                  }
                }

                addExecutionEvidence(
                    result.process_data, *executable, "UserAssist", timestamp,
                    "user=" + username +
                        ", run_count=" + std::to_string(run_count));
                result.userassist_count++;
              }
            }
          } catch (const std::exception& e) {
            logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "UserAssist пропущен для {}: {}", hive, e.what());
          }
        }

        if (ctx.config.enable_runmru) {
          try {
            auto values = parser.getKeyValues(hive, ctx.config.runmru_key);
            for (const auto& value : values) {
              std::string value_name = getLastPathComponent(value->getName(), '/');
              if (value_name.empty()) continue;
              if (toLowerAscii(value_name) == "mrulist" ||
                  toLowerAscii(value_name) == "mrulistex") {
                continue;
              }

              const std::string command = value->getDataAsString();
              auto executable = extractExecutableFromCommand(command);
              if (!executable.has_value()) continue;

              addExecutionEvidence(result.process_data, *executable, "RunMRU", "",
                                  "user=" + username + ", value=" + value_name);
              result.runmru_count++;
            }
          } catch (const std::exception& e) {
            logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "RunMRU пропущен для {}: {}", hive, e.what());
          }
        }
      };

  std::size_t userassist_count = 0;
  std::size_t runmru_count = 0;
  const bool use_parallel = ctx.enable_parallel_user_hives &&
                            ctx.worker_threads > 1 && user_hives.size() > 1;
  if (use_parallel) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Execution(UserAssist/RunMRU): параллельный режим (workers={})",
                  std::min<std::size_t>(ctx.worker_threads, user_hives.size()));
  }
  if (!use_parallel) {
    HiveBatchResult sequential_result;
    RegistryAnalysis::RegistryParser local_parser;
    for (const fs::path& hive_path : user_hives) {
      process_hive(local_parser, hive_path, sequential_result);
    }
    mergeProcessDataMaps(process_data, std::move(sequential_result.process_data));
    userassist_count = sequential_result.userassist_count;
    runmru_count = sequential_result.runmru_count;
  } else {
    const std::size_t workers =
        std::min<std::size_t>(ctx.worker_threads, user_hives.size());
    std::atomic<std::size_t> next_index{0};
    std::vector<std::future<HiveBatchResult>> futures;
    futures.reserve(workers);

    for (std::size_t worker = 0; worker < workers; ++worker) {
      futures.push_back(std::async(std::launch::async, [&]() {
        RegistryAnalysis::RegistryParser local_parser;
        HiveBatchResult worker_result;
        while (true) {
          const std::size_t index = next_index.fetch_add(1);
          if (index >= user_hives.size()) break;
          process_hive(local_parser, user_hives[index], worker_result);
        }
        return worker_result;
      }));
    }

    for (auto& future : futures) {
      auto worker_result = future.get();
      mergeProcessDataMaps(process_data, std::move(worker_result.process_data));
      userassist_count += worker_result.userassist_count;
      runmru_count += worker_result.runmru_count;
    }
  }

  logger->info("UserAssist: добавлено {} кандидат(ов)", userassist_count);
  logger->info("RunMRU: добавлено {} кандидат(ов)", runmru_count);
}

}  // namespace WindowsDiskAnalysis
