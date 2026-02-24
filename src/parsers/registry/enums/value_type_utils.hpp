/// @file value_type_utils.hpp
/// @brief Утилиты для работы с типами значений реестра Windows

#pragma once

#include <string>

#include "value_type.hpp"

namespace RegistryAnalysis {

/// @brief Преобразует тип значения реестра в строковое представление
/// @param[in] type Тип значения реестра
/// @return Строковое имя типа
/// @note Возвращает "UNKNOWN_TYPE_<номер>" для неизвестных типов
std::string valueTypeToString(RegistryValueType type);

/// @brief Проверяет, является ли тип строковым
/// @param[in] type Тип значения реестра
/// @return true если тип является строковым (REG_SZ, REG_EXPAND_SZ, REG_LINK)
bool isStringType(RegistryValueType type);

/// @brief Проверяет, является ли тип целочисленным
/// @param[in] type Тип значения реестра
/// @return true если тип является целочисленным (REG_DWORD,
/// REG_DWORD_BIG_ENDIAN, REG_QWORD)
bool isIntegerType(RegistryValueType type);

}
