#include "vss_analyzer.hpp"

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
    if (ec || !matched) return std::nullopt;
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

VSSAnalyzer::VSSAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void VSSAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();

  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      enabled_ = config.getBool("Recovery", "EnableVSS", enabled_);
      enable_pagefile_ =
          config.getBool("Recovery", "EnablePagefile", enable_pagefile_);
      enable_memory_ = config.getBool("Recovery", "EnableMemory", enable_memory_);
      enable_unallocated_ =
          config.getBool("Recovery", "EnableUnallocated", enable_unallocated_);
      binary_scan_max_mb_ =
          static_cast<std::size_t>(std::max(
              1, config.getInt("Recovery", "BinaryScanMaxMB",
                               static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(
          std::max(1, config.getInt("Recovery", "MaxCandidatesPerSource",
                                    static_cast<int>(max_candidates_per_source_))));
      unallocated_image_path_ =
          config.getString("Recovery", "UnallocatedImagePath", "");
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки VSS");
    logger->debug("Ошибка чтения [Recovery]: {}", e.what());
  }
}

std::vector<RecoveryEvidence> VSSAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->debug("VSS-анализ отключен в конфигурации");
    return {};
  }

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;

  const fs::path svi_dir = fs::path(disk_root) / "System Volume Information";
  if (const auto resolved_svi = findPathCaseInsensitive(svi_dir);
      resolved_svi.has_value()) {
    std::error_code ec;
    for (const auto& entry :
         fs::recursive_directory_iterator(*resolved_svi,
                                          fs::directory_options::skip_permission_denied,
                                          ec)) {
      if (ec) break;
      if (!entry.is_regular_file()) continue;
      const std::string lowered_name = toLowerAscii(entry.path().filename().string());
      if (lowered_name.find("shadowcopy") == std::string::npos &&
          lowered_name.find(".pf") == std::string::npos) {
        continue;
      }

      auto evidence = scanRecoveryFile(entry.path(), "VSS", "VSS", max_bytes,
                                       max_candidates_per_source_);
      results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                     std::make_move_iterator(evidence.end()));
    }
  }

  if (enable_pagefile_) {
    const std::vector<fs::path> pagefile_candidates = {
        fs::path(disk_root) / "pagefile.sys", fs::path(disk_root) / "swapfile.sys",
        fs::path(disk_root) / "Windows" / "Temp" / "pagefile.sys"};
    for (const auto& candidate : pagefile_candidates) {
      const auto resolved = findPathCaseInsensitive(candidate);
      if (!resolved.has_value()) continue;

      auto evidence = scanRecoveryFile(*resolved, "Pagefile", "Pagefile",
                                       max_bytes, max_candidates_per_source_);
      results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                     std::make_move_iterator(evidence.end()));
    }
  }

  if (enable_memory_) {
    const std::vector<fs::path> memory_candidates = {
        fs::path(disk_root) / "hiberfil.sys",
        fs::path(disk_root) / "Windows" / "MEMORY.DMP",
        fs::path(disk_root) / "MEMORY.DMP"};
    for (const auto& candidate : memory_candidates) {
      const auto resolved = findPathCaseInsensitive(candidate);
      if (!resolved.has_value()) continue;

      auto evidence = scanRecoveryFile(*resolved, "Memory", "Memory", max_bytes,
                                       max_candidates_per_source_);
      results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                     std::make_move_iterator(evidence.end()));
    }
  }

  if (enable_unallocated_ && !unallocated_image_path_.empty()) {
    const fs::path image_path(unallocated_image_path_);
    std::error_code ec;
    if (fs::exists(image_path, ec) && !ec && fs::is_regular_file(image_path, ec) &&
        !ec) {
      auto evidence = scanRecoveryFile(image_path, "Unallocated", "Unallocated",
                                       max_bytes, max_candidates_per_source_);
      results.insert(results.end(), std::make_move_iterator(evidence.begin()),
                     std::make_move_iterator(evidence.end()));
    }
  }

  logger->info("Recovery(VSS/Pagefile/Memory/Unallocated): добавлено {} "
               "кандидат(ов)",
               results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
