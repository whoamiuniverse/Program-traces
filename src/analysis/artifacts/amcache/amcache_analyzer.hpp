/// @file amcache_analyzer.hpp
/// @brief Анализатор данных Amcache.hve для извлечения сведений о приложениях

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "parsers/registry/parser/parser.hpp"
#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @struct AmcacheConfig
/// @brief Параметры чтения Amcache для конкретной версии Windows
struct AmcacheConfig {
  std::string amcache_path;               ///< Путь к Amcache.hve
  std::vector<std::string> amcache_keys;  ///< Ключи для анализа в Amcache
};

/// @class AmcacheAnalyzer
/// @brief Анализатор Amcache.hve для извлечения информации о запущенных
/// программах
class AmcacheAnalyzer {
 public:
  /// @brief Создаёт анализатор Amcache
  /// @param parser Парсер кустов реестра Windows
  /// @param os_version Идентификатор версии ОС для выбора секции конфигурации
  /// @param ini_path Путь к INI-файлу с параметрами анализа Amcache
  AmcacheAnalyzer(std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
                  std::string os_version, std::string ini_path);

  /// @brief Собирает записи Amcache с подключённого диска
  /// @param disk_root Корневой путь подключённого диска Windows
  /// @return Список извлечённых записей приложений из Amcache
  /// @throws ConfigException При ошибке чтения конфигурации
  /// @throws RegistryException При ошибке чтения куста реестра
  std::vector<AmcacheEntry> collect(const std::string& disk_root) const;

 private:
  /// @brief Загружает параметры анализа Amcache из INI-конфигурации
  /// @throws ConfigException При отсутствии требуемых параметров
  void loadConfiguration();

  /// @brief Преобразует значения реестра раздела InventoryApplication в запись
  /// @param values Набор значений реестра одного элемента приложения
  /// @return Нормализованная запись AmcacheEntry
  static AmcacheEntry processInventoryApplicationEntry(
      const std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>&
          values);

  std::unique_ptr<RegistryAnalysis::IRegistryParser>
      parser_;  ///< Парсер для доступа к значениям реестра
  std::string os_version_;   ///< Версия ОС для выбора конфигурационного профиля
  std::string ini_path_;     ///< Путь к INI-файлу с настройками
  std::string amcache_path_;  ///< Путь к файлу Amcache.hve относительно диска
  std::vector<std::string>
      amcache_keys_;  ///< Список ключей реестра, подлежащих разбору
};

}
