/// @file prefetch_analyzer.hpp
/// @brief Анализатор Prefetch-файлов Windows

#pragma once

#include <filesystem>
#include <map>
#include <memory>

#include "../../../../parsers/prefetch/parser/parser.hpp"
#include "../data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @brief Конфигурация анализа Prefetch для конкретной версии ОС
struct PrefetchConfig {
  std::string prefetch_path;  ///< Путь к папке Prefetch
};

/// @brief Анализатор Prefetch-файлов Windows
class PrefetchAnalyzer {
 public:
  /// @brief Конструктор анализатора Prefetch
  /// @param parser Экземпляр парсера Prefetch-файлов
  /// @param os_version Версия целевой ОС (должна соответствовать секции в INI)
  /// @param ini_path Путь к конфигурационному файлу с путями Prefetch
  PrefetchAnalyzer(std::unique_ptr<PrefetchAnalysis::IPrefetchParser> parser,
                   std::string os_version, const std::string& ini_path);

  /// @brief Сбор информации о процессах из Prefetch-файлов
  /// @param disk_root Корневой путь анализируемого диска
  /// @return Карта информации о процессах (ключ - путь к исполняемому файлу)
  std::vector<ProcessInfo> collect(const std::string& disk_root);

 private:
  /// @brief Загружает конфигурации путей Prefetch из INI-файла
  /// @param ini_path Путь к конфигурационному файлу
  void loadConfigurations(const std::string& ini_path);

  std::unique_ptr<PrefetchAnalysis::IPrefetchParser>
      parser_;  ///< Парсер Prefetch-файлов
  std::map<std::string, PrefetchConfig>
      configs_;             ///< Конфигурации для версий ОС
  std::string os_version_;  ///< Целевая версия ОС
};

}
