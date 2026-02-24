/// @file data.hpp
/// @brief Конкретная реализация хранения данных реестра Windows

#pragma once

#include <string>
#include <vector>

#include "errors/registry_exception.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "idata.hpp"

namespace RegistryAnalysis {

/// @class RegistryData
/// @brief Конкретная реализация хранения данных реестра Windows
/// @details Хранит данные значения реестра в виде варианта (variant) с
/// проверкой типов
class RegistryData final : public IRegistryData {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор для пустого значения (REG_NONE)
  /// @param[in] name Имя значения
  explicit RegistryData(std::string name = "");

  /// @brief Конструктор для строковых типов
  /// @param[in] name Имя значения
  /// @param[in] data Строковые данные
  /// @param[in] type Тип значения (REG_SZ, REG_EXPAND_SZ, REG_LINK)
  RegistryData(std::string name, std::string data, RegistryValueType type);

  /// @brief Конструктор для бинарных типов
  /// @param[in] name Имя значения
  /// @param[in] data Бинарные данные
  /// @param[in] type Тип значения (REG_BINARY, REG_RESOURCE_LIST)
  RegistryData(std::string name, std::vector<uint8_t> data,
               RegistryValueType type);

  /// @brief Конструктор для 32-битных целых типов
  /// @param[in] name Имя значения
  /// @param[in] data 32-битное целое
  /// @param[in] type Тип значения (REG_DWORD, REG_DWORD_BIG_ENDIAN)
  RegistryData(std::string name, uint32_t data, RegistryValueType type);

  /// @brief Конструктор для 64-битных целых (REG_QWORD)
  /// @param[in] name Имя значения
  /// @param[in] data 64-битное целое
  RegistryData(std::string name, uint64_t data);

  /// @brief Конструктор для мультистрок (REG_MULTI_SZ)
  /// @param[in] name Имя значения
  /// @param[in] data Вектор строк
  RegistryData(std::string name, std::vector<std::string> data);

  /// @}

  /// @name Методы доступа
  /// @{

  /// @copydoc IRegistryData::getName
  [[nodiscard]] const std::string& getName() const noexcept override;

  /// @copydoc IRegistryData::getType
  [[nodiscard]] RegistryValueType getType() const noexcept override;

  /// @copydoc IRegistryData::getDataAsString
  [[nodiscard]] std::string getDataAsString() const override;

  /// @copydoc IRegistryData::getData
  [[nodiscard]] const RegistryValueVariant& getData() const noexcept override;

  /// @copydoc IRegistryData::isNone
  [[nodiscard]] bool isNone() const noexcept override;

  /// @}

  /// @name Специализированные методы доступа
  /// @{

  /// @copydoc IRegistryData::getAsString
  [[nodiscard]] const std::string& getAsString() const override;

  /// @copydoc IRegistryData::getAsBinary
  [[nodiscard]] const std::vector<uint8_t>& getAsBinary() const override;

  /// @copydoc IRegistryData::getAsDword
  [[nodiscard]] uint32_t getAsDword() const override;

  /// @copydoc IRegistryData::getAsQword
  [[nodiscard]] uint64_t getAsQword() const override;

  /// @copydoc IRegistryData::getAsMultiString
  [[nodiscard]] const std::vector<std::string>& getAsMultiString()
      const override;

  /// @}

 private:
  /// @brief Проверить соответствие типа данных
  /// @param[in] actual Фактический тип значения
  /// @param[in] allowed Разрешенные типы значений
  /// @throw InvalidType если тип не соответствует разрешенным
  static void validateType(RegistryValueType actual,
                           std::initializer_list<RegistryValueType> allowed);

  std::string name_;           ///< Имя значения реестра
  RegistryValueVariant data_;  ///< Данные значения (вариант)
  RegistryValueType type_ = RegistryValueType::REG_NONE;  ///< Тип значения
};

}
