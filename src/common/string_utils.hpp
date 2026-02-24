/// @file string_utils.hpp
/// @brief Набор inline-утилит для базовой обработки строк и путей

#pragma once

#include <algorithm>
#include <cctype>
#include <sstream>
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
/// @details Пустые токены пропускаются, каждый непустой токен дополнительно
/// обрезается по краям.
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
