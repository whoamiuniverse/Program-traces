/// @file csv_exporter_filtering.hpp
/// @brief Правила фильтрации метрик и tamper-логика для CSV-экспорта.

#pragma once

#include <set>
#include <string>
#include <vector>

#include "csv_exporter.hpp"
#include "csv_exporter_utils.hpp"
#include "parsers/prefetch/metadata/file_metric.hpp"

namespace WindowsDiskAnalysis {
namespace CsvExporterFiltering {

/// @brief Правила фильтрации метрик, подготовленные для быстрого применения.
struct MetricFilterRules {
  std::size_t max_metric_names = 200;
  std::vector<std::string> skip_prefixes;
  std::vector<std::string> skip_contains;
  std::set<std::string> skip_exact;
  bool drop_short_upper_tokens = true;
  std::size_t short_upper_token_max_length = 3;
  bool drop_hex_like_tokens = true;
  std::size_t hex_like_min_length = 16;
  bool drop_upper_alnum_tokens = true;
  std::size_t upper_alnum_min_length = 8;
};

/// @brief Нормализует список фильтров метрик к lower-case без пустых значений.
std::vector<std::string> normalizeFilterTokens(
    const std::vector<std::string>& values);

/// @brief Строит runtime-правила фильтрации метрик из конфигурации.
MetricFilterRules buildMetricFilterRules(const CSVExportOptions& options);

/// @brief Проверяет необходимость отбрасывания имени метрики.
bool shouldSkipMetricFilename(const std::string& metric_filename,
                              const MetricFilterRules& rules);

/// @brief Формирует финальный набор метрик для CSV c фильтрами и лимитом.
std::vector<std::string> buildMetricValuesForCsv(
    const std::vector<PrefetchAnalysis::FileMetric>& metrics,
    const MetricFilterRules& rules);

/// @brief Добавляет источник артефактов с нормализацией имени.
void addEvidenceSource(AggregatedData& data, std::string source);

/// @brief Добавляет tamper-флаг, если он не пуст.
void addTamperFlag(AggregatedData& data, std::string flag);

/// @brief Проверяет наличие конкретного источника в строке.
bool hasEvidenceSource(const AggregatedData& data, const std::string& source);

/// @brief Проверяет наличие любого источника из заданного списка.
bool hasAnyEvidenceSource(const AggregatedData& data,
                          const std::vector<std::string>& sources);

/// @brief Проверяет, является ли источник сетевым контекстом.
bool isNetworkContextSource(const std::string& source);

/// @brief Проверяет, относится ли timeline-запись к сетевому контексту.
bool isNetworkTimelineArtifact(const std::string& timeline);

/// @brief Выводит дополнительные tamper-флаги по правилам корреляции.
void deriveTamperFlags(AggregatedData& data, const CSVExportOptions& options);

/// @brief Обновляет минимальное время первого наблюдения.
void updateRowFirstSeen(AggregatedData& data, const std::string& timestamp);

/// @brief Обновляет максимальное время последнего наблюдения.
void updateRowLastSeen(AggregatedData& data, const std::string& timestamp);

}  // namespace CsvExporterFiltering
}  // namespace WindowsDiskAnalysis
