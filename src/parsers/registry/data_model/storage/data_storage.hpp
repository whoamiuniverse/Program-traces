/// @file data_storage.hpp
/// @brief Структуры для хранения и преобразования данных реестра Windows

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace RegistryAnalysis {

/// @brief Тип-вариант для хранения различных типов данных реестра
/// @details Объединяет все возможные типы данных значений реестра:
///    - std::monostate: пустое значение (REG_NONE)
///    - std::string: строковые типы (REG_SZ, REG_EXPAND_SZ, REG_LINK)
///    - std::vector<uint8_t>: бинарные данные (REG_BINARY,
///      REG_RESOURCE_LIST)
///    - uint32_t: 32-битные целые (REG_DWORD, REG_DWORD_BIG_ENDIAN)
///    - uint64_t: 64-битные целые (REG_QWORD)
///    - std::vector<std::string>: мультистроки (REG_MULTI_SZ)
using RegistryValueVariant =
    std::variant<std::monostate, std::string, std::vector<uint8_t>, uint32_t,
                 uint64_t, std::vector<std::string>>;

/// @class DataToStringVisitor
/// @brief Визуализатор данных реестра в строковое представление
/// @details Реализует паттерн посетителя для преобразования различных типов
/// данных реестра в удобочитаемые строковые представления
class DataToStringVisitor {
 public:
  /// @name Методы преобразования
  /// @{

  /// @brief Преобразование пустого значения (REG_NONE)
  /// @return Пустая строка
  std::string operator()(const std::monostate&) const;

  /// @brief Преобразование строкового значения
  /// @return Исходная строка без изменений
  std::string operator()(const std::string& s) const;

  /// @brief Преобразование бинарных данных в HEX-строку
  /// @return Строка с HEX-представлением байтов, разделенных пробелами
  std::string operator()(const std::vector<uint8_t>& data) const;

  /// @brief Преобразование 32-битного целого в строку
  /// @return Строковое представление числа
  std::string operator()(uint32_t value) const;

  /// @brief Преобразование 64-битного целого в строку
  /// @return Строковое представление числа
  std::string operator()(uint64_t value) const;

  /// @brief Преобразование мультистроки в единую строку
  /// @return Строка с элементами, разделенными точкой с запятой
  std::string operator()(const std::vector<std::string>& data) const;

  /// @}
};

}
