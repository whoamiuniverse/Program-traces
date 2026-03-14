/// @file registry_log_analyzer.cpp
/// @brief Реализация анализатора recovery для LOG1/LOG2 и related registry logs.

#include "registry_log_analyzer.hpp"

#include <algorithm>
#include <filesystem>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::toLowerAscii;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

/// @brief Проверяет, относится ли файл к транзакционным логам hive.
/// @param path Путь файла.
/// @return `true`, если файл является кандидатом recovery.
bool isRegistryTransactionLogFile(const fs::path& path) {
  const std::string name_lower = toLowerAscii(path.filename().string());
  if (name_lower.ends_with(".log1")) return true;
  if (name_lower.ends_with(".log2")) return true;
  if (name_lower.ends_with(".blf")) return true;
  if (name_lower.ends_with(".regtrans-ms")) return true;
  return false;
}

}  // namespace

RegistryLogAnalyzer::RegistryLogAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void RegistryLogAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      enabled_ = config.getBool("Recovery", "EnableRegistryLogsRecovery", enabled_);
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));
      registry_config_path_ = config.getString("Recovery", "RegistryConfigPath",
                                               registry_config_path_);
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки RegistryLogAnalyzer");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Recovery] для RegistryLogs: {}", e.what());
  }
}

std::vector<RecoveryEvidence> RegistryLogAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "RegistryLog-анализ отключен в конфигурации");
    return {};
  }

  const fs::path registry_root = fs::path(disk_root) / registry_config_path_;
  const auto resolved_registry_root = findPathCaseInsensitive(registry_root);
  if (!resolved_registry_root.has_value()) {
    logger->info("Recovery(RegistryLogs LOG1/LOG2): binary=0 total=0");
    return {};
  }

  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::size_t binary_count = 0;

  std::error_code ec;
  for (const auto& entry : fs::recursive_directory_iterator(
           *resolved_registry_root, fs::directory_options::skip_permission_denied,
           ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    if (!isRegistryTransactionLogFile(entry.path())) continue;

    auto evidence = scanRecoveryFileBinary(entry.path(), "Registry",
                                           "RegistryLog(binary)", max_bytes,
                                           max_candidates_per_source_);
    for (auto& item : evidence) {
      item.tamper_flag = "registry_transaction_log_evidence";
    }
    binary_count += evidence.size();
    appendUniqueEvidence(results, evidence, dedup);
  }

  logger->info("Recovery(RegistryLogs LOG1/LOG2): binary={} total={}",
               binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
