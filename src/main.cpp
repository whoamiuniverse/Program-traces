#include <filesystem>
#include <iostream>
#include <string>

#include "analysis/artifacts/orchestrator/windows_disk_analyzer.hpp"
#include "errors/csv_export_exception.hpp"
#include "infra/cli/cli_options.hpp"
#include "infra/logging/logger.hpp"

namespace {

constexpr int kExitSuccess = 0;
constexpr int kExitInvalidArguments = 1;
constexpr int kExitFilesystemError = 2;
constexpr int kExitAnalysisError = 3;
constexpr int kExitCsvExportError = 4;

}  // namespace

int main(int argc, char* argv[]) {
  std::string error_message;
  const auto options = ProgramTraces::Cli::parseArguments(argc, argv, error_message);
  if (!options.has_value()) {
    std::cerr << error_message << "\n\n";
    ProgramTraces::Cli::printUsage(argv[0]);
    return kExitInvalidArguments;
  }

  if (options->show_help) {
    ProgramTraces::Cli::printUsage(argv[0]);
    return kExitSuccess;
  }
  if (options->show_version) {
    ProgramTraces::Cli::printVersion();
    return kExitSuccess;
  }

  if (!options->log_path.empty()) {
    GlobalLogger::setLogPath(options->log_path);
  }

  const auto logger = GlobalLogger::get();

  try {
    const std::string disk_root_display =
        options->disk_root == "auto"
            ? std::string("auto (автоматический поиск Windows-тома)")
            : options->disk_root;

    std::cout << "\n=== Запуск анализа диска Windows ===\n"
              << "\tКорневая директория: " << disk_root_display << "\n"
              << "\tКонфигурационный файл: " << options->config_path << "\n"
              << "\tВыходной CSV-файл: " << options->output_path << "\n"
              << "\tRecovery CSV: "
              << (options->export_recovery_csv ? "включен" : "выключен");
    if (options->export_recovery_csv) {
      if (!options->recovery_output_path.empty()) {
        std::cout << " (" << options->recovery_output_path << ")";
      } else {
        std::cout << " (<output_base>_recovery.csv)";
      }
    }
    std::cout << "\n";
    if (!options->log_path.empty()) {
      std::cout << "\tЛог-файл: " << options->log_path << "\n";
    }
    std::cout << '\n';

    WindowsDiskAnalysis::WindowsDiskAnalyzer analyzer(options->disk_root,
                                                      options->config_path);
    analyzer.analyze(
        options->output_path,
        {.export_recovery_csv = options->export_recovery_csv,
         .recovery_output_path = options->recovery_output_path});

    std::cout << "\n=== Анализ успешно завершен ===\n"
              << "Результаты сохранены в: " << options->output_path << "\n";
  } catch (const std::filesystem::filesystem_error& e) {
    logger->error("Ошибка файловой системы: {}", e.what());
    return kExitFilesystemError;
  } catch (const WindowsDiskAnalysis::CsvExportException& e) {
    logger->error("{}", e.what());
    return kExitCsvExportError;
  } catch (const std::exception& e) {
    logger->error("{}", e.what());
    return kExitAnalysisError;
  }

  return kExitSuccess;
}
