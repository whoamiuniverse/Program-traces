/// @file cli_options.cpp
/// @brief Реализация разбора аргументов командной строки Program traces.

#include "infra/cli/cli_options.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace ProgramTraces::Cli {

void printUsage(const char* program_name) {
  std::cout
      << "Использование:\n"
      << "  " << program_name
      << " [-l <logfile>] [-r|-R <path>] "
         "<корень_диска|auto> <config.ini> <output.csv>\n"
      << "  " << program_name
      << " [-l <logfile>] [-r|-R <path>] "
         "<config.ini> <output.csv>\n"
      << "  " << program_name
      << " [-d <корень_диска|auto>] -c <config.ini> -o <output.csv> "
         "[-l <logfile>] [-r|-R <path>]\n\n"
      << "Опции:\n"
      << "  -h, --help       Показать эту справку\n"
      << "  -v, --version    Показать версию программы\n"
      << "  -d, --disk-root  Корень Windows-диска или auto\n"
      << "  -c, --config     Путь к config.ini\n"
      << "  -o, --output     Путь к основному output CSV\n"
      << "  -l, --log <path> Путь к лог-файлу\n"
      << "  -r, --recovery-csv\n"
      << "                   Дополнительно создать <output_base>_recovery.csv\n"
      << "  -R, --recovery-output <path>\n"
      << "                   Сохранить recovery CSV в указанный файл\n"
      << "  -i, --image <path>\n"
      << "                   Путь к образу диска для сигнатурного "
         "сканирования\n\n"
      << "Режим auto:\n"
      << "  Если disk-root не указан, используется auto.\n"
      << "  В этом режиме программа ищет Windows-том среди смонтированных.\n"
      << "  Для явного выбора тома используйте -d/--disk-root.\n\n"
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
  if (argc <= 1) {
    CliOptions options;
    options.show_help = true;
    return options;
  }

  const auto readOptionValue = [&](const std::string& option_name, int& index,
                                   std::string& output_value) -> bool {
    if (index + 1 >= argc) {
      error_message = "Опция " + option_name + " требует значение";
      return false;
    }
    output_value = argv[++index];
    return true;
  };

  CliOptions options;
  std::vector<std::string> positional;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "-h" || argument == "--help") {
      options.show_help = true;
      continue;
    }
    if (argument == "-v" || argument == "--version") {
      options.show_version = true;
      continue;
    }
    if (argument == "-r" || argument == "--recovery-csv") {
      options.export_recovery_csv = true;
      continue;
    }
    if (argument == "-R" || argument == "--recovery-output") {
      if (!readOptionValue(argument, index, options.recovery_output_path)) {
        return std::nullopt;
      }
      options.export_recovery_csv = true;
      continue;
    }
    if (argument == "-l" || argument == "--log") {
      if (!readOptionValue(argument, index, options.log_path)) {
        return std::nullopt;
      }
      continue;
    }
    if (argument == "-d" || argument == "--disk-root") {
      if (!readOptionValue(argument, index, options.disk_root)) {
        return std::nullopt;
      }
      continue;
    }
    if (argument == "-c" || argument == "--config") {
      if (!readOptionValue(argument, index, options.config_path)) {
        return std::nullopt;
      }
      continue;
    }
    if (argument == "-o" || argument == "--output") {
      if (!readOptionValue(argument, index, options.output_path)) {
        return std::nullopt;
      }
      continue;
    }
    if (argument == "-i" || argument == "--image") {
      if (!readOptionValue(argument, index, options.image_path)) {
        return std::nullopt;
      }
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

  const bool has_named_config = !options.config_path.empty();
  const bool has_named_output = !options.output_path.empty();
  const bool has_named_io = has_named_config || has_named_output;

  if (has_named_io) {
    if (!has_named_config || !has_named_output) {
      error_message =
          "При использовании --config/--output нужно указать оба параметра";
      return std::nullopt;
    }
    if (!positional.empty()) {
      error_message =
          "Позиционные аргументы нельзя смешивать с --config/--output";
      return std::nullopt;
    }
  } else if (positional.size() == 2) {
    options.config_path = positional[0];
    options.output_path = positional[1];
  } else if (positional.size() == 3) {
    options.disk_root = positional[0];
    options.config_path = positional[1];
    options.output_path = positional[2];
  } else {
    error_message = "Ожидается 2 или 3 позиционных аргумента, либо -c/-o";
    return std::nullopt;
  }

  if (!options.recovery_output_path.empty() &&
      options.recovery_output_path == options.output_path) {
    error_message = "Recovery CSV должен отличаться от основного output CSV";
    return std::nullopt;
  }

  return options;
}

}  // namespace ProgramTraces::Cli
