/// @file idata.hpp
/// @brief Интерфейс для работы с данными реестра Windows

#pragma once

#include "parsers/registry/data_model/storage/data_storage.hpp"
#include "parsers/registry/enums/value_type.hpp"

namespace RegistryAnalysis {

/// @class IRegistryData
/// @interface IRegistryData
/// @brief Интерфейс для работы с данными реестра Windows
/// @details Определяет общие методы для доступа к данным различных типов
/// значений реестра
class IRegistryData {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Виртуальный деструктор по умолчанию
  virtual ~IRegistryData() = default;

  /// @}

  /// @name Методы доступа
  /// @{

  /// @brief Получить имя значения
  /// @return Ссылка на строку с именем значения
  virtual const std::string& getName() const noexcept = 0;

  /// @brief Получить тип значения
  /// @return Тип значения реестра (перечисление RegistryValueType)
  virtual RegistryValueType getType() const noexcept = 0;

  /// @brief Получить данные в строковом представлении
  /// @return Строковое представление данных значения
  virtual std::string getDataAsString() const = 0;

  /// @brief Получить данные в виде варианта
  /// @return Константная ссылка на вариант с данными
  virtual const RegistryValueVariant& getData() const noexcept = 0;

  /// @brief Проверить, является ли значение пустым (REG_NONE)
  /// @return true если тип значения REG_NONE, иначе false
  virtual bool isNone() const noexcept = 0;

  /// @}

  /// @name Специализированные методы доступа
  /// @{

  /// @brief Получить данные как строку (для строковых типов)
  /// @return Ссылка на строковое значение
  virtual const std::string& getAsString() const = 0;

  /// @brief Получить данные как бинарный массив
  /// @return Ссылка на вектор байтов
  virtual const std::vector<uint8_t>& getAsBinary() const = 0;

  /// @brief Получить данные как 32-битное целое
  /// @return 32-битное беззнаковое целое
  virtual uint32_t getAsDword() const = 0;

  /// @brief Получить данные как 64-битное целое
  /// @return 64-битное беззнаковое целое
  virtual uint64_t getAsQword() const = 0;

  /// @brief Получить данные как массив строк
  /// @return Ссылка на вектор строк
  virtual const std::vector<std::string>& getAsMultiString() const = 0;

  /// @}
};

}
