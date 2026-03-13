#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "analysis/artifacts/orchestrator/windows_disk_analyzer.hpp"
#include "errors/csv_export_exception.hpp"
#include "infra/logging/logger.hpp"

namespace {

constexpr int kExitSuccess = 0;
constexpr int kExitInvalidArguments = 1;
constexpr int kExitFilesystemError = 2;
constexpr int kExitAnalysisError = 3;
constexpr int kExitCsvExportError = 4;

struct CliOptions {
  std::string disk_root = "auto";
  std::string config_path;
  std::string output_path;
  std::string log_path;
  bool show_help = false;
  bool show_version = false;
};

void printUsage(const char* program_name) {
  std::cout
      << "Использование:\n"
      << "  " << program_name
      << " [--log <logfile>] <корень_диска|auto> <config.ini> <output.csv>\n"
      << "  " << program_name
      << " [--log <logfile>] <config.ini> <output.csv>\n\n"
      << "Опции:\n"
      << "  -h, --help       Показать эту справку\n"
      << "  --version        Показать версию программы\n"
      << "  --log <path>     Путь к лог-файлу\n\n"
      << "Коды выхода:\n"
      << "  0  Успешное завершение\n"
      << "  1  Ошибка аргументов командной строки\n"
      << "  2  Ошибка файловой системы\n"
      << "  3  Ошибка анализа (парсинг / конфиг / ОС)\n"
      << "  4  Ошибка экспорта CSV\n";
}

void printVersion() {
  std::cout << "Program traces " << PROGRAM_TRACES_VERSION << '\n';
}

std::optional<CliOptions> parseArguments(int argc, char* argv[],
                                         std::string& error_message) {
  CliOptions options;
  std::vector<std::string> positional;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "-h" || argument == "--help") {
      options.show_help = true;
      continue;
    }
    if (argument == "--version") {
      options.show_version = true;
      continue;
    }
    if (argument == "--log") {
      if (index + 1 >= argc) {
        error_message = "Опция --log требует путь к файлу";
        return std::nullopt;
      }
      options.log_path = argv[++index];
      continue;
    }
    if (!argument.empty() && argument.front() == '-') {
      error_message = "Неизвестная опция: " + argument;
      return std::nullopt;
    }
    positional.push_back(argument);
  }

  if (options.show_help || options.show_version) {
    return options;
  }

  if (positional.size() == 2) {
    options.config_path = positional[0];
    options.output_path = positional[1];
    return options;
  }
  if (positional.size() == 3) {
    options.disk_root = positional[0];
    options.config_path = positional[1];
    options.output_path = positional[2];
    return options;
  }

  error_message = "Ожидается 2 или 3 позиционных аргумента";
  return std::nullopt;
}

}  // namespace

int main(int argc, char* argv[]) {
  std::string error_message;
  const auto options = parseArguments(argc, argv, error_message);
  if (!options.has_value()) {
    std::cerr << error_message << "\n\n";
    printUsage(argv[0]);
    return kExitInvalidArguments;
  }

  if (options->show_help) {
    printUsage(argv[0]);
    return kExitSuccess;
  }
  if (options->show_version) {
    printVersion();
    return kExitSuccess;
  }

  if (!options->log_path.empty()) {
    GlobalLogger::setLogPath(options->log_path);
  }

  const auto logger = GlobalLogger::get();

  try {
    std::cout << "\n=== Запуск анализа диска Windows ===\n"
              << "\tКорневая директория: " << options->disk_root << "\n"
              << "\tКонфигурационный файл: " << options->config_path << "\n"
              << "\tВыходной CSV-файл: " << options->output_path << "\n";
    if (!options->log_path.empty()) {
      std::cout << "\tЛог-файл: " << options->log_path << "\n";
    }
    std::cout << '\n';

    WindowsDiskAnalysis::WindowsDiskAnalyzer analyzer(options->disk_root,
                                                      options->config_path);
    analyzer.analyze(options->output_path);

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
