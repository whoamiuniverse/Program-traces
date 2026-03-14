/// @file windows_disk_analyzer_tamper.cpp
/// @brief Tamper-rules и экспорт WindowsDiskAnalyzer.

#include "windows_disk_analyzer.hpp"

#include <algorithm>
#include <filesystem>
#include <set>
#include <string_view>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/config_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

namespace {

bool endsWithCaseInsensitive(const std::string& value,
                             const std::string& suffix) {
  if (value.size() < suffix.size()) {
    return false;
  }

  const std::string lowered_value = to_lower(value);
  const std::string lowered_suffix = to_lower(suffix);
  return lowered_value.rfind(lowered_suffix) ==
         lowered_value.size() - lowered_suffix.size();
}

bool looksLikeProcessImage(const std::string& process_key) {
  if (process_key.empty()) {
    return false;
  }

  const std::string filename = getLastPathComponent(process_key, '/');
  const std::string candidate =
      filename.empty() ? getLastPathComponent(process_key, '\\') : filename;
  const std::string normalized = candidate.empty() ? process_key : candidate;
  return endsWithCaseInsensitive(normalized, ".exe") ||
         endsWithCaseInsensitive(normalized, ".com") ||
         endsWithCaseInsensitive(normalized, ".bat") ||
         endsWithCaseInsensitive(normalized, ".cmd") ||
         endsWithCaseInsensitive(normalized, ".ps1") ||
         endsWithCaseInsensitive(normalized, ".msi");
}

std::string buildPrefetchLookupKey(const std::string& process_key) {
  std::string filename = getLastPathComponent(process_key, '/');
  if (filename.empty()) {
    filename = getLastPathComponent(process_key, '\\');
  }
  if (filename.empty()) {
    filename = process_key;
  }
  return to_lower(filename);
}

bool hasAnySource(const ProcessInfo& info,
                  const std::vector<std::string>& runtime_sources) {
  for (const auto& source : info.evidence_sources) {
    for (const auto& expected : runtime_sources) {
      if (to_lower(source) == to_lower(expected)) {
        return true;
      }
    }
  }
  return false;
}

std::set<std::string> buildPrefetchFilenameSet(const std::string& disk_root,
                                               const std::string& config_path,
                                               const std::string& os_version) {
  std::set<std::string> results;
  Config config(config_path, false, false);
  std::string prefetch_relative = WindowsDiskAnalysis::ConfigUtils::
      getWithVersionFallback(config, os_version, "PrefetchPath");
  trim(prefetch_relative);
  std::ranges::replace(prefetch_relative, '\\', '/');
  if (prefetch_relative.empty()) {
    return results;
  }

  const fs::path prefetch_candidate = fs::path(disk_root) / prefetch_relative;
  const auto resolved = PathUtils::findPathCaseInsensitive(prefetch_candidate);
  if (!resolved.has_value()) {
    return results;
  }

  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(*resolved, ec)) {
    if (ec || !entry.is_regular_file()) {
      continue;
    }

    const std::string extension = to_lower(entry.path().extension().string());
    if (extension != ".pf") {
      continue;
    }

    std::string stem = to_lower(entry.path().stem().string());
    trim(stem);
    if (stem.empty()) {
      continue;
    }
    results.insert(stem);

    const std::size_t hash_sep = stem.rfind('-');
    if (hash_sep != std::string::npos && hash_sep > 0) {
      results.insert(stem.substr(0, hash_sep));
    }
  }

  return results;
}

}  // namespace

void WindowsDiskAnalyzer::applyGlobalTamperFlags() {
  for (auto& [_, info] : process_data_) {
    for (const auto& global_flag : global_tamper_flags_) {
      appendTamperFlag(info, global_flag);
    }
  }
}

void WindowsDiskAnalyzer::applyTamperRules() {
  if (!tamper_options_.enable_prefetch_missing_rule) {
    return;
  }

  const std::set<std::string> prefetch_names = buildPrefetchFilenameSet(
      disk_root_, config_path_, os_info_.ini_version);
  for (auto& [process_key, info] : process_data_) {
    if (tamper_options_.prefetch_missing_require_process_image &&
        !looksLikeProcessImage(process_key) &&
        !looksLikeProcessImage(info.filename)) {
      continue;
    }

    if (prefetch_names.find(buildPrefetchLookupKey(process_key)) !=
            prefetch_names.end() ||
        prefetch_names.find(buildPrefetchLookupKey(info.filename)) !=
            prefetch_names.end()) {
      continue;
    }

    if (hasAnySource(info, tamper_options_.runtime_sources)) {
      appendTamperFlag(info, "prefetch_missing_but_other_artifacts_present");
    }
  }
}

void WindowsDiskAnalyzer::exportCsv(const std::string& output_path,
                                    const AnalyzeOutputOptions& options) {
  const auto logger = GlobalLogger::get();
  logger->info("Этап 7/7: экспорт CSV");

  ensureDirectoryExists(output_path);
  if (options.export_recovery_csv && !options.recovery_output_path.empty()) {
    ensureDirectoryExists(options.recovery_output_path);
  }
  CSVExporter::exportToCSV(
      output_path, autorun_entries_, process_data_, network_connections_,
      amcache_entries_, recovery_evidence_,
      {.export_recovery_csv = options.export_recovery_csv,
       .recovery_output_path = options.recovery_output_path});
  logger->info("Этап 7/7 завершен: экспорт в \"{}\"", output_path);
}

}  // namespace WindowsDiskAnalysis
