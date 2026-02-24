/// @file iparser.hpp
/// @brief Интерфейс для парсинга файлов реестра Windows

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "parsers/registry/data_model/idata.hpp"

namespace RegistryAnalysis {

/// @class IRegistryParser
/// @interface IRegistryParser
/// @brief Интерфейс для работы с парсером реестра Windows
/// @details Определяет основные операции для извлечения данных из файлов
/// реестра
class IRegistryParser {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Виртуальный деструктор по умолчанию
  virtual ~IRegistryParser() = default;

  /// @}

  /// @name Методы получения значений
  /// @{

  /// @brief Получить все значения в указанном разделе реестра
  /// @param[in] registry_file_path Путь к файлу реестра
  /// @param[in] registry_key_path Путь к разделу реестра
  /// @return Вектор объектов данных реестра
  virtual std::vector<std::unique_ptr<IRegistryData>> getKeyValues(
      const std::string& registry_file_path,
      const std::string& registry_key_path) = 0;

  /// @brief Получить конкретное значение реестра
  /// @param[in] registry_file_path Путь к файлу реестра
  /// @param[in] registry_value_path Полный путь к значению реестра
  /// @return Указатель на объект данных реестра или nullptr если не найдено
  virtual std::unique_ptr<IRegistryData> getSpecificValue(
      const std::string& registry_file_path,
      const std::string& registry_value_path) = 0;

  /// @brief Получить список подразделов в указанном ключе
  /// @param[in] registry_file_path Путь к файлу реестра
  /// @param[in] registry_key_path Путь к разделу реестра
  /// @return Вектор имен подразделов
  virtual std::vector<std::string> listSubkeys(
      const std::string& registry_file_path,
      const std::string& registry_key_path) = 0;

  /// @}
};

}
