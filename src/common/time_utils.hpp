/// @file time_utils.hpp
/// @brief Утилиты преобразования времени между FILETIME, Unix time и строкой

#pragma once

#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

/// @struct FILETIME
/// @brief Кроссплатформенное представление структуры Windows FILETIME
/// @details Хранит 64-битное значение времени в виде двух 32-битных частей.
typedef struct {
  uint32_t dwLowDateTime;   ///< Младшие 32 бита значения FILETIME
  uint32_t dwHighDateTime;  ///< Старшие 32 бита значения FILETIME
} FILETIME;

/// @struct SYSTEMTIME
/// @brief Кроссплатформенное представление структуры Windows SYSTEMTIME
/// @details Содержит разложенное по полям UTC-время.
typedef struct {
  uint16_t wYear;          ///< Год (например, 2026)
  uint16_t wMonth;         ///< Месяц [1..12]
  uint16_t wDayOfWeek;     ///< День недели [0..6], где 0 - воскресенье
  uint16_t wDay;           ///< День месяца [1..31]
  uint16_t wHour;          ///< Часы [0..23]
  uint16_t wMinute;        ///< Минуты [0..59]
  uint16_t wSecond;        ///< Секунды [0..59]
  uint16_t wMilliseconds;  ///< Миллисекунды [0..999]
} SYSTEMTIME;

/// @brief Конвертирует 64-битное FILETIME в SYSTEMTIME
/// @param filetime Значение FILETIME
/// @return Структура SYSTEMTIME
/// @details При невозможности преобразования (например, `gmtime` вернул `null`)
/// возвращается нулевая структура `SYSTEMTIME`.
inline SYSTEMTIME filetimeToSystemTime(uint64_t filetime) {
  SYSTEMTIME st{};

  // Константа для перевода в Unix-время (100-нс интервалы с 1601-01-01)
  constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;

  // Конвертация в секунды и наносекунды
  uint64_t total_ns = (filetime - EPOCH_DIFFERENCE);
  time_t unix_seconds = total_ns / 10000000ULL;
  uint32_t nanoseconds = (total_ns % 10000000ULL) * 100;

  // Преобразование в UTC время
  tm* tm_value = gmtime(&unix_seconds);
  if (!tm_value) return st;

  st.wYear = static_cast<uint16_t>(tm_value->tm_year + 1900);
  st.wMonth = static_cast<uint16_t>(tm_value->tm_mon + 1);
  st.wDayOfWeek = static_cast<uint16_t>(tm_value->tm_wday);
  st.wDay = static_cast<uint16_t>(tm_value->tm_mday);
  st.wHour = static_cast<uint16_t>(tm_value->tm_hour);
  st.wMinute = static_cast<uint16_t>(tm_value->tm_min);
  st.wSecond = static_cast<uint16_t>(tm_value->tm_sec);
  st.wMilliseconds = static_cast<uint16_t>(nanoseconds / 1000000);

  return st;
}

/// @brief Конвертирует FILETIME в строку формата YYYY-MM-DD HH:MM:SS
/// @param filetime 64-битное значение FILETIME
/// @return Строковое представление времени
/// @note Возвращает `N/A`, если входное значение равно `0`.
inline std::string filetimeToString(uint64_t filetime) {
  if (filetime == 0) return "N/A";

  SYSTEMTIME st = filetimeToSystemTime(filetime);

  std::ostringstream oss;
  oss << std::setfill('0') << std::setw(4) << st.wYear << "-" << std::setw(2)
      << st.wMonth << "-" << std::setw(2) << st.wDay << " " << std::setw(2)
      << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2)
      << st.wSecond;

  return oss.str();
}

/// @brief Конвертирует FILETIME в Unix timestamp
/// @param filetime 64-битное значение FILETIME
/// @return Время в формате Unix timestamp
/// @warning Функция предполагает валидное значение `filetime` не меньше эпохи
/// Unix; проверка диапазона не выполняется.
inline time_t filetimeToUnixTime(uint64_t filetime) {
  constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;
  return (filetime - EPOCH_DIFFERENCE) / 10000000ULL;
}

/// @brief Форматирует Unix timestamp в строку (UTC)
/// @param timestamp Unix timestamp
/// @return Строковое представление времени
/// @note Возвращает `N/A`, если `gmtime` не смогла преобразовать время.
inline std::string unixTimeToString(time_t timestamp) {
  struct tm* tm = gmtime(&timestamp);
  if (!tm) return "N/A";

  std::ostringstream oss;
  oss << std::setfill('0') << std::setw(4) << (tm->tm_year + 1900) << "-"
      << std::setw(2) << (tm->tm_mon + 1) << "-" << std::setw(2) << tm->tm_mday
      << " " << std::setw(2) << tm->tm_hour << ":" << std::setw(2) << tm->tm_min
      << ":" << std::setw(2) << tm->tm_sec;

  return oss.str();
}

/// @brief Форматирует Unix timestamp в строку (локальное время)
/// @param timestamp Unix timestamp
/// @return Строковое представление времени
/// @note Возвращает `N/A`, если `localtime` не смогла преобразовать время.
inline std::string unixTimeToLocalString(time_t timestamp) {
  struct tm* tm = localtime(&timestamp);
  if (!tm) return "N/A";

  std::ostringstream oss;
  oss << std::setfill('0') << std::setw(4) << (tm->tm_year + 1900) << "-"
      << std::setw(2) << (tm->tm_mon + 1) << "-" << std::setw(2) << tm->tm_mday
      << " " << std::setw(2) << tm->tm_hour << ":" << std::setw(2) << tm->tm_min
      << ":" << std::setw(2) << tm->tm_sec;

  return oss.str();
}

/// @brief Безопасно конвертирует uint64_t в строку времени
/// @param time_value Временная метка в uint64_t формате
/// @param use_utc Использовать ли UTC (true) или локальное время (false)
/// @return Строковое представление времени
/// @throw std::overflow_error Если значение превышает диапазон time_t
inline std::string safeTimeToString(uint64_t time_value, bool use_utc = true) {
  // Проверка диапазона
  constexpr uint64_t max_time_t = std::numeric_limits<time_t>::max();
  if (time_value > max_time_t) {
    throw std::overflow_error("Превышение диапазона time_t");
  }

  // Конвертация
  auto timestamp = static_cast<time_t>(time_value);
  return use_utc ? unixTimeToString(timestamp)
                 : unixTimeToLocalString(timestamp);
}

/// @brief Конвертирует время выполнения в строку (совместимость)
/// @param time_value Временная метка
/// @return Строковое представление времени
/// @note Использует локальное время для совместимости
inline std::string convert_run_times(uint64_t time_value) {
  return safeTimeToString(time_value, false);
}
