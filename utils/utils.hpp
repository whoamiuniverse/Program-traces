#pragma once

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/// @brief Удаляет пробельные символы в начале и конце строки
/// @param str Строка для обработки (изменяется на месте)
inline void trim(std::string& str) {
  if (str.empty()) return;

  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };

  // Удаление пробелов в конце
  str.erase(std::find_if(str.rbegin(), str.rend(), not_space).base(),
            str.end());

  // Удаление пробелов в начале
  str.erase(str.begin(), std::ranges::find_if(str, not_space));
}

/// @brief Создаёт обрезанную копию строки
/// @param str Исходная строка
/// @return Обрезанная копия строки
inline std::string trim_copy(std::string str) {
  trim(str);
  return str;
}

/// @brief Разделяет строку на подстроки по указанному разделителю
/// @param str Исходная строка для разделения
/// @param delimiter Символ-разделитель
/// @return Вектор подстрок
inline std::vector<std::string> split(const std::string& str, char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream token_stream(str);

  while (std::getline(token_stream, token, delimiter)) {
    if (!token.empty()) {
      tokens.push_back(trim_copy(token));
    }
  }

  return tokens;
}

/// @brief Извлекает последний компонент из пути
/// @param path Путь в файловой системе
/// @param separator Разделитель пути
/// @return Последний компонент пути
inline std::string getLastPathComponent(const std::string& path,
                                        char separator = '/') {
  if (path.empty()) return "";

  // Удаляем конечные разделители
  size_t end = path.length();
  while (end > 0 && path[end - 1] == separator) --end;
  if (end == 0) return "";

  // Находим начало последнего компонента
  size_t start = path.find_last_of(separator, end - 1);
  return (start == std::string::npos) ? path.substr(0, end)
                                      : path.substr(start + 1, end - start - 1);
}

/// @brief Заменяет все вхождения подстроки
/// @param str Исходная строка
/// @param from Что заменять
/// @param to На что заменять
/// @return Строка с заменёнными вхождениями
inline std::string replace_all(std::string str, const std::string& from,
                               const std::string& to) {
  if (from.empty()) return str;

  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
  return str;
}

/// @brief Преобразует строку в нижний регистр
/// @param str Исходная строка
/// @return Строка в нижнем регистре
inline std::string to_lower(std::string str) {
  std::ranges::transform(str, str.begin(),
                         [](unsigned char c) { return std::tolower(c); });
  return str;
}

/// @brief Проверяет, начинается ли строка с префикса
/// @param str Исходная строка
/// @param prefix Искомый префикс
/// @return true если строка начинается с префикса
inline bool starts_with(const std::string& str, const std::string& prefix) {
  return str.size() >= prefix.size() &&
         str.compare(0, prefix.size(), prefix) == 0;
}

/// @brief Проверяет, заканчивается ли строка суффиксом
/// @param str Исходная строка
/// @param suffix Искомый суффикс
/// @return true если строка заканчивается суффиксом
inline bool ends_with(const std::string& str, const std::string& suffix) {
  return str.size() >= suffix.size() &&
         str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Структуры для эмуляции Windows FILETIME/SYSTEMTIME
typedef struct {
  uint32_t dwLowDateTime;
  uint32_t dwHighDateTime;
} FILETIME;

typedef struct {
  uint16_t wYear;
  uint16_t wMonth;
  uint16_t wDayOfWeek;
  uint16_t wDay;
  uint16_t wHour;
  uint16_t wMinute;
  uint16_t wSecond;
  uint16_t wMilliseconds;
} SYSTEMTIME;

/// @brief Конвертирует 64-битное FILETIME в SYSTEMTIME
/// @param filetime Значение FILETIME
/// @return Структура SYSTEMTIME
inline SYSTEMTIME filetimeToSystemTime(uint64_t filetime) {
  SYSTEMTIME st = {0};

  // Константа для перевода в Unix-время (100-нс интервалы с 1601-01-01)
  constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;

  // Конвертация в секунды и наносекунды
  uint64_t total_ns = (filetime - EPOCH_DIFFERENCE);
  time_t unix_seconds = total_ns / 10000000ULL;
  uint32_t nanoseconds = (total_ns % 10000000ULL) * 100;

  // Преобразование в UTC время
  tm* tm = gmtime(&unix_seconds);
  if (!tm) return st;

  st.wYear = tm->tm_year + 1900;
  st.wMonth = tm->tm_mon + 1;
  st.wDay = tm->tm_mday;
  st.wHour = tm->tm_hour;
  st.wMinute = tm->tm_min;
  st.wSecond = tm->tm_sec;
  st.wMilliseconds = nanoseconds / 1000000;

  return st;
}

/// @brief Конвертирует FILETIME в строку формата YYYY-MM-DD HH:MM:SS
/// @param filetime 64-битное значение FILETIME
/// @return Строковое представление времени
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
inline time_t filetimeToUnixTime(uint64_t filetime) {
  constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;
  return (filetime - EPOCH_DIFFERENCE) / 10000000ULL;
}

/// @brief Форматирует Unix timestamp в строку (UTC)
/// @param timestamp Unix timestamp
/// @return Строковое представление времени
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
