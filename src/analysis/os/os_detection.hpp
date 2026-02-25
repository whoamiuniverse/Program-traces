/// @file os_detection.hpp
/// @brief Реализация определения версии Windows через анализ реестра

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "errors/os_detection_exception.hpp"
#include "parsers/registry/parser/iparser.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "common/utils.hpp"
#include "ios_detection.hpp"
#include "os_info.hpp"

namespace WindowsVersion {

/// @class OSDetection
/// @brief Реализация определения версии Windows через анализ реестра
class OSDetection final : public IOSDetection {
 public:
  /// @brief Конструктор объекта определения ОС
  /// @param parser Реализация парсера реестра
  /// @param config Параметры конфигурации
  /// @param device_root_path Корневой путь целевого устройства
  OSDetection(std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
              Config&& config, std::string device_root_path);

  /// @brief Деструктор по умолчанию
  ~OSDetection() override = default;

  /// @brief Определяет версию Windows
  /// @return Структура с информацией об ОС
  /// @throws OSDetectionException при ошибке определения
  [[nodiscard]] OSInfo detect() override;

 private:
  /// @brief Загружает конфигурацию для определения ОС
  /// @throws OSDetectionException при невалидной конфигурации
  void loadConfiguration();

  /// @brief Извлекает информацию об ОС из значений реестра
  /// @param values Значения реестра для обработки
  /// @param info Структура OSInfo для заполнения
  /// @param version_name Имя версии конфигурации
  void extractOSInfo(
      const std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>&
          values,
      OSInfo& info, const std::string& version_name) const;

  /// @brief Формирует полное название ОС из компонентов
  /// @param info Структура OSInfo для финализации
  void determineFullOSName(OSInfo& info) const;

  /// @brief Выбирает секцию INI для анализаторов артефактов
  /// @param info Информация об ОС из реестра
  /// @return Имя секции версии (например, Windows10)
  [[nodiscard]] std::string resolveIniVersion(const OSInfo& info) const;

  /// @brief Возвращает путь к SYSTEM hive для найденной конфигурации версии
  /// @param version_name Имя версии из [General]
  /// @param cfg Конфигурация чтения SOFTWARE hive
  [[nodiscard]] std::string resolveSystemHiveRelativePath(
      const std::string& version_name, const VersionConfig& cfg) const;

  /// @brief Читает ProductType из SYSTEM hive и обновляет OSInfo
  /// @param system_hive_path Полный путь к файлу SYSTEM
  /// @param info Структура OSInfo для обновления
  void enrichFromSystemHive(const std::string& system_hive_path,
                            OSInfo& info) const;

  /// @brief Читает индекс текущего control set из Select/Current
  /// @param system_hive_path Полный путь к файлу SYSTEM
  /// @return Индекс control set (например 1 -> ControlSet001)
  [[nodiscard]] std::optional<uint32_t> readCurrentControlSetIndex(
      const std::string& system_hive_path) const;

  /// @brief Проверяет, является ли ОС серверной редакцией
  /// @param info Структура OSInfo для проверки
  /// @return True для серверной редакции, false иначе
  bool isServerSystem(const OSInfo& info) const;

  std::unique_ptr<RegistryAnalysis::IRegistryParser>
      parser_;                    ///< Экземпляр парсера реестра
  Config config_;                 ///< Параметры конфигурации
  std::string device_root_path_;  ///< Корневой путь устройства
  std::map<std::string, VersionConfig>
      version_configs_;  ///< Конфигурации версий
  std::vector<std::string>
      version_order_;  ///< Порядок версий из [General] Versions
  std::vector<std::string>
      default_server_keywords_;  ///< Ключевые слова для идентификации серверных
                                 ///< редакций
  std::map<uint32_t, std::string>
      client_builds;  ///< Соответствия номеров сборок клиентских версий
  std::map<uint32_t, std::string>
      server_builds;  ///< Соответствия номеров сборок серверных версий
};

}
