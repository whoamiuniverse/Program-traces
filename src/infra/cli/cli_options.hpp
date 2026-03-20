/// @file cli_options.hpp
/// @brief Разбор аргументов командной строки Program traces.

#pragma once

#include <optional>
#include <string>

namespace ProgramTraces::Cli {

/// @struct CliOptions
/// @brief Нормализованные параметры запуска, извлеченные из argv.
struct CliOptions {
  std::string disk_root = "auto";  ///< Корень Windows-диска или `auto`.
  std::string config_path;          ///< Путь к конфигурации.
  std::string output_path;          ///< Путь к основному CSV-отчету.
  std::string log_path;             ///< Путь к лог-файлу (опционально).
  bool export_recovery_csv = false;  ///< Создавать recovery CSV.
  std::string recovery_output_path;   ///< Явный путь recovery CSV (опционально).
  std::string image_path;             ///< Путь к образу диска для сигнатурного сканирования.
  bool show_help = false;             ///< Печатать help и завершиться.
  bool show_version = false;          ///< Печатать версию и завершиться.
};

/// @brief Печатает справку по аргументам командной строки.
/// @param program_name Имя исполняемого файла из argv[0].
void printUsage(const char* program_name);

/// @brief Печатает версию программы.
void printVersion();

/// @brief Разбирает параметры командной строки в структуру @ref CliOptions.
/// @param argc Количество аргументов.
/// @param argv Массив аргументов.
/// @param error_message Текст ошибки разбора при неуспехе.
/// @return Заполненный @ref CliOptions или @c std::nullopt при ошибке.
[[nodiscard]] std::optional<CliOptions> parseArguments(
    int argc, char* argv[], std::string& error_message);

}  // namespace ProgramTraces::Cli

