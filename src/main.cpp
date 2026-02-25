#include <filesystem>
#include <iostream>
#include <string>

#include "analysis/artifacts/orchestrator/windows_disk_analyzer.hpp"
#include "infra/logging/logger.hpp"

int main(int argc, char* argv[]) {
  // Проверка количества аргументов
  if (argc != 3 && argc != 4) {
    std::cerr
        << "Использование:\n"
        << "  " << argv[0] << " <корень_диска|auto> <конфиг> <выходной_файл>\n"
        << "  " << argv[0] << " <конфиг> <выходной_файл>\n"
        << "Пример:\n"
        << "  " << argv[0]
        << " /mnt/windows/ /путь/к/config.ini /отчеты/анализ.csv\n"
        << "  " << argv[0] << " /путь/к/config.ini /отчеты/анализ.csv\n";
    return 1;
  }

  const auto logger = GlobalLogger::get();

  try {
    // Получение аргументов
    std::string disk_root;
    std::string config_path;
    std::string output_path;

    if (argc == 4) {
      disk_root = argv[1];
      config_path = argv[2];
      output_path = argv[3];
    } else {
      disk_root = "auto";
      config_path = argv[1];
      output_path = argv[2];
    }

    std::cout << "\n=== Запуск анализа диска Windows ===\n"
              << "\tКорневая директория: " << disk_root << "\n"
              << "\tКонфигурационный файл: " << config_path << "\n"
              << "\tВыходной CSV-файл: " << output_path << "\n\n";

    // Создание и запуск анализатора
    WindowsDiskAnalysis::WindowsDiskAnalyzer analyzer(disk_root, config_path);
    analyzer.analyze(output_path);

    std::cout << "\n=== Анализ успешно завершен ===\n"
              << "Результаты сохранены в: " << output_path << "\n";
  } catch (const std::filesystem::filesystem_error& e) {
    logger->error("Ошибка файловой системы: {}", e.what());
    return 2;
  } catch (const std::exception& e) {
    logger->error("{}", e.what());
    return 3;
  }

  return 0;
}
