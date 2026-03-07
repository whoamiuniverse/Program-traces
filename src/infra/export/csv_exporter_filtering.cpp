/// @file csv_exporter_filtering.cpp
/// @brief Реализация правил фильтрации метрик и tamper-логики для CSV-экспорта.

#include "csv_exporter_filtering.hpp"

#include <algorithm>
#include <filesystem>
#include <string>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "csv_exporter_utils.hpp"

namespace fs = std::filesystem;

using WindowsDiskAnalysis::CsvExporterUtils::sortAndUnique;
using WindowsDiskAnalysis::CsvExporterUtils::toLowerAscii;
using WindowsDiskAnalysis::CsvExporterUtils::normalizeEvidenceSource;

namespace WindowsDiskAnalysis {
namespace CsvExporterFiltering {

std::vector<std::string> normalizeFilterTokens(
    const std::vector<std::string>& values) {
  std::vector<std::string> normalized;
  normalized.reserve(values.size());

  for (std::string token : values) {
    trim(token);
    token = toLowerAscii(std::move(token));
    if (!token.empty()) {
      normalized.push_back(std::move(token));
    }
  }

  sortAndUnique(normalized);
  return normalized;
}

MetricFilterRules buildMetricFilterRules(const CSVExportOptions& options) {
  MetricFilterRules rules;
  rules.max_metric_names = options.max_metric_names;
  rules.skip_prefixes = normalizeFilterTokens(options.metric_skip_prefixes);
  rules.skip_contains = normalizeFilterTokens(options.metric_skip_contains);

  for (const std::string& exact_value : options.metric_skip_exact) {
    std::string token = toLowerAscii(trim_copy(exact_value));
    if (!token.empty()) {
      rules.skip_exact.insert(std::move(token));
    }
  }

  rules.drop_short_upper_tokens = options.drop_short_upper_tokens;
  rules.short_upper_token_max_length =
      std::max<std::size_t>(1, options.short_upper_token_max_length);
  rules.drop_hex_like_tokens = options.drop_hex_like_tokens;
  rules.hex_like_min_length = std::max<std::size_t>(1, options.hex_like_min_length);
  rules.drop_upper_alnum_tokens = options.drop_upper_alnum_tokens;
  rules.upper_alnum_min_length =
      std::max<std::size_t>(1, options.upper_alnum_min_length);

  return rules;
}

namespace {

bool hasFileExtension(const std::string& filename) {
  return filename.find('.') != std::string::npos;
}

bool isAllUpperAsciiLetters(const std::string& value) {
  if (value.empty()) return false;
  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    if (ch < 'A' || ch > 'Z') return false;
  }
  return true;
}

bool isMostlyHexLikeToken(const std::string& value, const std::size_t min_length) {
  if (value.size() < min_length) return false;
  bool has_digit = false;
  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    const bool is_hex =
        (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
        (ch >= 'A' && ch <= 'F') || ch == '_';
    if (!is_hex) return false;
    if (ch >= '0' && ch <= '9') has_digit = true;
  }
  return has_digit;
}

bool isUpperAlphaNumUnderscoreToken(const std::string& value,
                                    const std::size_t min_length) {
  if (value.size() < min_length) return false;
  bool has_digit = false;
  bool has_letter = false;
  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    const bool is_upper = (ch >= 'A' && ch <= 'Z');
    const bool is_digit = (ch >= '0' && ch <= '9');
    const bool is_separator = (ch == '_');
    if (!is_upper && !is_digit && !is_separator) return false;
    has_digit = has_digit || is_digit;
    has_letter = has_letter || is_upper;
  }
  return has_digit && has_letter;
}

bool shouldSkipByUserRules(const std::string& metric_filename_lower,
                           const MetricFilterRules& rules) {
  if (rules.skip_exact.contains(metric_filename_lower)) return true;
  for (const std::string& prefix : rules.skip_prefixes) {
    if (metric_filename_lower.rfind(prefix, 0) == 0) return true;
  }
  for (const std::string& token : rules.skip_contains) {
    if (metric_filename_lower.find(token) != std::string::npos) return true;
  }
  return false;
}

}  // anonymous namespace

bool shouldSkipMetricFilename(const std::string& metric_filename,
                              const MetricFilterRules& rules) {
  if (metric_filename.empty()) return true;

  const std::string lowered = toLowerAscii(metric_filename);
  if (shouldSkipByUserRules(lowered, rules)) return true;

  if (!hasFileExtension(metric_filename)) {
    if (rules.drop_short_upper_tokens &&
        metric_filename.size() <= rules.short_upper_token_max_length &&
        isAllUpperAsciiLetters(metric_filename)) {
      return true;
    }
    if (rules.drop_hex_like_tokens &&
        isMostlyHexLikeToken(metric_filename, rules.hex_like_min_length)) {
      return true;
    }
    if (rules.drop_upper_alnum_tokens &&
        isUpperAlphaNumUnderscoreToken(metric_filename,
                                       rules.upper_alnum_min_length)) {
      return true;
    }
  }

  return false;
}

std::vector<std::string> buildMetricValuesForCsv(
    const std::vector<PrefetchAnalysis::FileMetric>& metrics,
    const MetricFilterRules& rules) {
  std::vector<std::string> metric_values;
  metric_values.reserve(metrics.size());

  for (const auto& metric : metrics) {
    fs::path file_path(metric.getFilename());
    std::string metric_filename = file_path.filename().string();
    metric_filename.erase(
        std::remove(metric_filename.begin(), metric_filename.end(), '\0'),
        metric_filename.end());
    trim(metric_filename);
    if (shouldSkipMetricFilename(metric_filename, rules)) continue;
    metric_values.push_back(std::move(metric_filename));
  }

  sortAndUnique(metric_values);

  if (rules.max_metric_names > 0 && metric_values.size() > rules.max_metric_names) {
    const std::size_t hidden_count = metric_values.size() - rules.max_metric_names;
    metric_values.resize(rules.max_metric_names);
    metric_values.push_back("[+" + std::to_string(hidden_count) + " скрыто]");
  }

  return metric_values;
}

void addEvidenceSource(AggregatedData& data, std::string source) {
  source = normalizeEvidenceSource(std::move(source));
  if (!source.empty()) {
    data.evidence_sources.insert(std::move(source));
  }
}

void addTamperFlag(AggregatedData& data, std::string flag) {
  trim(flag);
  if (!flag.empty()) {
    data.tamper_flags.insert(std::move(flag));
  }
}

bool hasEvidenceSource(const AggregatedData& data, const std::string& source) {
  return data.evidence_sources.contains(normalizeEvidenceSource(source));
}

bool hasAnyEvidenceSource(const AggregatedData& data,
                          const std::vector<std::string>& sources) {
  for (const auto& source : sources) {
    if (hasEvidenceSource(data, source)) return true;
  }
  return false;
}

bool isNetworkContextSource(const std::string& source) {
  return source == "NetworkEvent" || source == "NetworkProfile" ||
         source == "FirewallRule" || source == "BITS" || source == "SRUM" ||
         source == "Hosts";
}

bool isNetworkTimelineArtifact(const std::string& timeline) {
  if (timeline.empty()) return false;
  const std::string lowered = toLowerAscii(timeline);
  return lowered.find("[networkevent]") != std::string::npos ||
         lowered.find("[networkprofile]") != std::string::npos ||
         lowered.find("[firewallrule]") != std::string::npos ||
         lowered.find("[bits]") != std::string::npos ||
         lowered.find("[hosts]") != std::string::npos;
}

namespace {

bool isLikelyProcessImageName(const std::string& executable_name) {
  const std::string lowered = toLowerAscii(executable_name);
  for (const std::string_view ext :
       {".exe", ".com", ".bat", ".cmd", ".ps1", ".msi"}) {
    if (lowered.size() >= ext.size() &&
        lowered.rfind(ext) == lowered.size() - ext.size()) {
      return true;
    }
  }
  return false;
}

}  // anonymous namespace

void deriveTamperFlags(AggregatedData& data, const CSVExportOptions& options) {
  if (options.tamper_rule_prefetch_missing_enabled) {
    const bool has_prefetch = hasEvidenceSource(data, "Prefetch");
    const bool has_runtime_sources = hasAnyEvidenceSource(
        data, options.tamper_prefetch_missing_runtime_sources);
    const bool image_condition =
        !options.tamper_rule_prefetch_missing_require_process_image ||
        isLikelyProcessImageName(data.executable_name);

    if (!has_prefetch && has_runtime_sources && image_condition) {
      addTamperFlag(data, "prefetch_missing_but_other_artifacts_present");
    }
  }

  if (options.tamper_rule_amcache_deleted_trace_enabled && data.has_deleted_trace) {
    addTamperFlag(data, "amcache_deleted_trace");
  }

  if (options.tamper_rule_registry_inconsistency_enabled) {
    const bool has_registry_only_sources =
        hasAnyEvidenceSource(data, options.tamper_registry_only_sources);
    const bool has_strong_correlated_sources =
        hasAnyEvidenceSource(data, options.tamper_registry_strong_sources);
    if (has_registry_only_sources && !has_strong_correlated_sources) {
      addTamperFlag(data, "registry_inconsistency");
    }
  }
}

void updateRowFirstSeen(AggregatedData& data, const std::string& timestamp) {
  EvidenceUtils::updateTimestampMin(data.first_seen_utc, timestamp);
}

void updateRowLastSeen(AggregatedData& data, const std::string& timestamp) {
  EvidenceUtils::updateTimestampMax(data.last_seen_utc, timestamp);
}

}  // namespace CsvExporterFiltering
}  // namespace WindowsDiskAnalysis
