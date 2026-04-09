/// @file amcache_analyzer.hpp
/// @brief Анализатор данных Amcache.hve для извлечения сведений о приложениях

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

/// @struct AmcacheConfig
/// @brief Конфигурация для дополнительных ключей Amcache
struct AmcacheConfig {
  std::string inventory_application_key =
      "Root/InventoryApplication";  ///< Путь к ключу InventoryApplication.
  std::string inventory_shortcut_key =
      "Root/InventoryApplicationShortcut";  ///< Путь к ключу
                                            ///< InventoryApplicationShortcut.
  std::string inventory_driver_key =
      "Root/InventoryApplicationDriver";  ///< Путь к ключу
                                          ///< InventoryApplicationDriver
                                          ///< (Windows 11 24H2+).
  bool enable_inventory_application =
      true;                               ///< Включает сбор записей приложений.
  bool enable_inventory_shortcut = true;  ///< Включает сбор записей shortcut.
  bool enable_inventory_driver =
      true;  ///< Включает сбор записей драйверов (Windows 11 24H2+).
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

  /// @brief Парсит Root/InventoryApplication (установленные приложения).
  std::vector<AmcacheEntry> collectInventoryApplication(
      const std::string& hive_path) const;

  /// @brief Парсит Root/InventoryApplicationShortcut (ярлыки приложений).
  std::vector<AmcacheEntry> collectInventoryShortcut(
      const std::string& hive_path) const;

  /// @brief Парсит Root/InventoryApplicationDriver (Windows 11 24H2+).
  std::vector<AmcacheEntry> collectInventoryApplicationDriver(
      const std::string& hive_path) const;

  /// @brief Собирает записи из RecentFileCache.bcf (Windows 7 fallback).
  std::vector<AmcacheEntry> collectFromRecentFileCache(
      const std::string& path) const;

  std::unique_ptr<RegistryAnalysis::IRegistryParser>
      parser_;              ///< Парсер для доступа к значениям реестра
  std::string os_version_;  ///< Версия ОС для выбора конфигурационного профиля
  std::string ini_path_;    ///< Путь к INI-файлу с настройками
  std::string amcache_path_;  ///< Путь к файлу Amcache.hve относительно диска
  std::string recent_file_cache_path_;  ///< Путь к RecentFileCache.bcf.
  std::vector<std::string>
      amcache_keys_;      ///< Список ключей реестра, подлежащих разбору
  AmcacheConfig config_;  ///< Расширенная конфигурация дополнительных ключей
};

}  // namespace WindowsDiskAnalysis
