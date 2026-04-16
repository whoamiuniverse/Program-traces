/// @file csv_exporter_filtering.cpp
/// @brief Подготовка полей CSV без эвристического отбрасывания артефактов.

#include "csv_exporter_filtering.hpp"

#include <algorithm>
#include <string>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "csv_exporter_utils.hpp"

using WindowsDiskAnalysis::CsvExporterUtils::sortAndUnique;
using WindowsDiskAnalysis::CsvExporterUtils::toLowerAscii;
using WindowsDiskAnalysis::CsvExporterUtils::getFilenameFromPath;
using WindowsDiskAnalysis::CsvExporterUtils::normalizeEvidenceSource;

namespace WindowsDiskAnalysis {
namespace CsvExporterFiltering {

std::vector<std::string> buildMetricValuesForCsv(
    const std::vector<PrefetchAnalysis::FileMetric>& metrics) {
  std::vector<std::string> metric_values;
  metric_values.reserve(metrics.size());

  for (const auto& metric : metrics) {
    std::string metric_filename = getFilenameFromPath(metric.getFilename());
    metric_filename.erase(
        std::remove(metric_filename.begin(), metric_filename.end(), '\0'),
        metric_filename.end());
    trim(metric_filename);
    if (metric_filename.empty()) continue;
    metric_values.push_back(std::move(metric_filename));
  }

  sortAndUnique(metric_values);
  return metric_values;
}

void addEvidenceSource(AggregatedData& data, std::string source) {
  source = normalizeEvidenceSource(std::move(source));
  if (!source.empty()) {
    data.evidence_sources.insert(std::move(source));
  }
}

bool isNetworkContextSource(const std::string& source) {
  return source == "NetworkEvent" || source == "SRUM";
}

bool isNetworkTimelineArtifact(const std::string& timeline) {
  if (timeline.empty()) return false;
  const std::string lowered = toLowerAscii(timeline);
  return lowered.find("[networkevent]") != std::string::npos ||
         lowered.find("[srum]") != std::string::npos;
}

void updateRowFirstSeen(AggregatedData& data, const std::string& timestamp) {
  EvidenceUtils::updateTimestampMin(data.first_seen_utc, timestamp);
}

void updateRowLastSeen(AggregatedData& data, const std::string& timestamp) {
  EvidenceUtils::updateTimestampMax(data.last_seen_utc, timestamp);
}

}  // namespace CsvExporterFiltering
}  // namespace WindowsDiskAnalysis
