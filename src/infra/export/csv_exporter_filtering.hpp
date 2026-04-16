/// @file csv_exporter_filtering.hpp
/// @brief Подготовка данных для CSV-экспорта без потерь артефактов.

#pragma once

#include <string>
#include <vector>

#include "csv_exporter_utils.hpp"
#include "parsers/prefetch/metadata/file_metric.hpp"

namespace WindowsDiskAnalysis {
namespace CsvExporterFiltering {

/// @brief Формирует финальный набор metric filenames для CSV.
/// @details Удаляются только технические артефакты сериализации
///          (NUL-байты/пустые строки), без эвристического отбрасывания.
std::vector<std::string> buildMetricValuesForCsv(
    const std::vector<PrefetchAnalysis::FileMetric>& metrics);

/// @brief Добавляет источник артефактов с нормализацией имени.
void addEvidenceSource(AggregatedData& data, std::string source);

/// @brief Проверяет, является ли источник сетевым контекстом.
bool isNetworkContextSource(const std::string& source);

/// @brief Проверяет, относится ли timeline-запись к сетевому контексту.
bool isNetworkTimelineArtifact(const std::string& timeline);

/// @brief Обновляет минимальное время первого наблюдения.
void updateRowFirstSeen(AggregatedData& data, const std::string& timestamp);

/// @brief Обновляет максимальное время последнего наблюдения.
void updateRowLastSeen(AggregatedData& data, const std::string& timestamp);

}  // namespace CsvExporterFiltering
}  // namespace WindowsDiskAnalysis
