#include "usn_analyzer.hpp"

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) return input_path;

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) return std::nullopt;

  const fs::path relative = input_path.is_absolute()
                                ? input_path.relative_path()
                                : input_path;

  for (const fs::path& component_path : relative) {
    const std::string component = component_path.string();
    if (component.empty() || component == ".") continue;
    if (component == "..") {
      current = current.parent_path();
      continue;
    }

    const fs::path direct = current / component_path;
    ec.clear();
    if (fs::exists(direct, ec) && !ec) {
      current = direct;
      continue;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec || !fs::is_directory(current, ec) || ec) {
      return std::nullopt;
    }

    const std::string lowered = toLowerAscii(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;
      if (toLowerAscii(entry.path().filename().string()) == lowered) {
        current = entry.path();
        matched = true;
        break;
      }
    }

    if (ec || !matched) {
      return std::nullopt;
    }
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) return current;
  return std::nullopt;
}

std::size_t toByteLimit(const std::size_t mb) {
  constexpr std::size_t kMegabyte = 1024 * 1024;
  if (mb == 0) return kMegabyte;
  return mb * kMegabyte;
}

std::vector<RecoveryEvidence> scanRecoveryFile(
    const fs::path& file_path, const std::string& source,
    const std::string& recovered_from, const std::size_t max_bytes,
    const std::size_t max_candidates) {
  std::vector<RecoveryEvidence> results;
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value()) return results;

  const auto candidates =
      extractExecutableCandidatesFromBinary(*data_opt, max_candidates);
  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(file_path, ec));

  for (const auto& executable : candidates) {
    RecoveryEvidence evidence;
    evidence.executable_path = executable;
    evidence.source = source;
    evidence.recovered_from = recovered_from;
    evidence.timestamp = timestamp;
    evidence.details = file_path.filename().string();
    results.push_back(std::move(evidence));
  }
  return results;
}

}  // namespace

USNAnalyzer::USNAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void USNAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();

  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      enabled_ = config.getBool("Recovery", "EnableUSN", enabled_);
      enable_logfile_ = config.getBool("Recovery", "EnableLogFile", enable_logfile_);
      binary_scan_max_mb_ =
          static_cast<std::size_t>(std::max(
              1, config.getInt("Recovery", "BinaryScanMaxMB",
                               static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(
          std::max(1, config.getInt("Recovery", "MaxCandidatesPerSource",
                                    static_cast<int>(max_candidates_per_source_))));
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки USN");
    logger->debug("Ошибка чтения [Recovery]: {}", e.what());
  }
}

std::vector<RecoveryEvidence> USNAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->debug("USN-анализ отключен в конфигурации");
    return {};
  }

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;

  const std::vector<fs::path> usn_candidates = {
      fs::path(disk_root) / "$Extend" / "$UsnJrnl",
      fs::path(disk_root) / "$UsnJrnl",
      fs::path(disk_root) / "Windows" / "$UsnJrnl"};

  for (const auto& candidate : usn_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    auto evidence = scanRecoveryFile(*resolved, "USN", "USN", max_bytes,
                                     max_candidates_per_source_);
    results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                   std::make_move_iterator(evidence.end()));
  }

  if (enable_logfile_) {
    const std::vector<fs::path> logfile_candidates = {
        fs::path(disk_root) / "$LogFile", fs::path(disk_root) / "Windows" / "$LogFile"};
    for (const auto& candidate : logfile_candidates) {
      const auto resolved = findPathCaseInsensitive(candidate);
      if (!resolved.has_value()) continue;

      auto evidence = scanRecoveryFile(*resolved, "$LogFile", "$LogFile",
                                       max_bytes, max_candidates_per_source_);
      results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                     std::make_move_iterator(evidence.end()));
    }
  }

  logger->info("Recovery(USN/$LogFile): добавлено {} кандидат(ов)",
               results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
