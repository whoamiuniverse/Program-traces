/// @file data_builder.hpp
/// @brief Построитель объектов данных реестра

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "errors/registry_exception.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "idata.hpp"

namespace RegistryAnalysis {

/// @class RegistryDataBuilder
/// @brief Построитель объектов данных реестра
/// @details Реализует паттерн "Строитель" для создания объектов данных реестра,
///          обеспечивая валидность создаваемых объектов и проверку типов данных
class RegistryDataBuilder {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор по умолчанию
  RegistryDataBuilder();

  /// @}

  /// @name Основные методы конфигурации
  /// @{

  /// @brief Установить имя значения
  /// @param[in] name Имя значения реестра
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setName(const std::string& name);

  /// @brief Установить тип значения
  /// @param[in] type Тип значения реестра
  /// @return Ссылка на текущий объект построителя
  /// @throws TypeCompatibilityError Если тип не совместим с текущими данными
  RegistryDataBuilder& setType(RegistryValueType type);

  /// @}

  /// @name Специализированные методы установки данных
  /// @{

  /// @brief Установить строковые данные (REG_SZ)
  /// @param[in] data Строковые данные
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setString(const std::string& data);

  /// @brief Установить расширенную строку (REG_EXPAND_SZ)
  /// @param[in] data Строковые данные
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setExpandString(const std::string& data);

  /// @brief Установить бинарные данные (REG_BINARY)
  /// @param[in] data Бинарные данные
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setBinary(const std::vector<uint8_t>& data);

  /// @brief Установить DWORD значение (REG_DWORD)
  /// @param[in] data 32-битное целое
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setDword(uint32_t data);

  /// @brief Установить DWORD в обратном порядке байт (REG_DWORD_BIG_ENDIAN)
  /// @param[in] data 32-битное целое
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setDwordBigEndian(uint32_t data);

  /// @brief Установить QWORD значение (REG_QWORD)
  /// @param[in] data 64-битное целое
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setQword(uint64_t data);

  /// @brief Установить мультистроку (REG_MULTI_SZ)
  /// @param[in] data Вектор строк
  /// @return Ссылка на текущий объект построителя
  RegistryDataBuilder& setMultiString(const std::vector<std::string>& data);

  /// @}

  /// @brief Построить объект данных реестра
  /// @return Указатель на созданный объект данных
  /// @throws UnsupportedTypeError Если тип значения не поддерживается
  [[nodiscard]] std::unique_ptr<IRegistryData> build() const;

 private:
  /// @brief Проверить совместимость типа данных
  /// @param[in] type Проверяемый тип
  /// @throws TypeCompatibilityError Если тип не совместим с текущими данными
  void validateTypeCompatibility(RegistryValueType type) const;

  std::string name_;           ///< Имя значения
  RegistryValueVariant data_;  ///< Данные значения
  RegistryValueType type_;     ///< Тип значения
};

}
