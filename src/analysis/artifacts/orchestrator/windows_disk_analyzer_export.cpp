/// @file windows_disk_analyzer_export.cpp
/// @brief Экспорт результатов WindowsDiskAnalyzer.

#include "windows_disk_analyzer.hpp"

#include "infra/logging/logger.hpp"

namespace WindowsDiskAnalysis {

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
