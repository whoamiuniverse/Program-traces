/// @file number_utils.hpp
/// @brief Безопасные утилиты преобразования строк в беззнаковые целые числа

#pragma once

#include <cstdint>
#include <limits>
#include <string>

/// @brief Пытается распарсить строку как uint32_t (без знака, основание 10)
/// @param text Входная строка
/// @param value Результат парсинга при успехе
/// @return true, если строка полностью и корректно распарсена
/// @details Функция перехватывает все исключения стандартных конвертеров и
/// возвращает `false`, не распространяя исключения наружу.
inline bool tryParseUInt32(const std::string& text, uint32_t& value) {
  if (text.empty()) return false;

  try {
    size_t parsed_len = 0;
    const unsigned long long parsed = std::stoull(text, &parsed_len, 10);
    if (parsed_len != text.size()) return false;
    if (parsed >
        static_cast<unsigned long long>(std::numeric_limits<uint32_t>::max())) {
      return false;
    }

    value = static_cast<uint32_t>(parsed);
    return true;
  } catch (...) {
    return false;
  }
}

/// @brief Пытается распарсить строку как uint16_t (без знака, основание 10)
/// @param text Входная строка
/// @param value Результат парсинга при успехе
/// @return true, если строка полностью и корректно распарсена
/// @details Выполняет проверку диапазона через промежуточный `uint32_t`.
inline bool tryParseUInt16(const std::string& text, uint16_t& value) {
  uint32_t parsed = 0;
  if (!tryParseUInt32(text, parsed) ||
      parsed > static_cast<uint32_t>(std::numeric_limits<uint16_t>::max())) {
    return false;
  }

  value = static_cast<uint16_t>(parsed);
  return true;
}
