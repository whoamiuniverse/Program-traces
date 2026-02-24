/// @file value_type.hpp
/// @brief Модель данных значения реестра Windows

#pragma once

#include <cstdint>

namespace RegistryAnalysis {

/// @enum RegistryValueType
/// @brief Перечисление типов данных значений реестра Windows
/// @details Соответствует официальным типам данных реестра Windows с
/// сохранением оригинальных числовых идентификаторов. Поддерживает все основные
/// типы данных, используемые в системном реестре
enum class RegistryValueType : uint32_t {
  REG_NONE = 0,              ///< Не определенный тип (0)
  REG_SZ = 1,                ///< Строка с завершающим нулём (1)
  REG_EXPAND_SZ = 2,         ///< Строка с переменными окружения (2)
  REG_BINARY = 3,            ///< Бинарные данные (3)
  REG_DWORD = 4,             ///< 32-битное целое число (little-endian) (4)
  REG_DWORD_BIG_ENDIAN = 5,  ///< 32-битное целое (big-endian) (5)
  REG_LINK = 6,              ///< Символическая ссылка (Unicode) (6)
  REG_MULTI_SZ = 7,          ///< Массив строк с двойным нулём в конце (7)
  REG_RESOURCE_LIST = 8,     ///< Список ресурсов в аппаратном описании (8)
  REG_QWORD = 11             ///< 64-битное целое число (11)
};

}
