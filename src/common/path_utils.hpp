/// @file path_utils.hpp
/// @brief Общие inline-утилиты для работы с путями и файловой системой.

#pragma once

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

#include "common/string_utils.hpp"

namespace PathUtils {

/// @brief Нормализует разделители пути к POSIX-виду (`/`).
/// @param path Исходный путь.
/// @return Путь с разделителями `/`.
[[nodiscard]] inline std::string normalizePathSeparators(std::string path) {
  std::ranges::replace(path, '\\', '/');
  return path;
}

/// @brief Ищет путь в файловой системе без учета регистра каждого компонента.
/// @details Утилита полезна при анализе Windows-путей на case-sensitive ФС.
/// @param input_path Путь-кандидат.
/// @param error_reason Необязательная строка для диагностического сообщения.
/// @return Разрешенный путь или `std::nullopt`, если путь найти не удалось.
[[nodiscard]] inline std::optional<std::filesystem::path>
findPathCaseInsensitive(const std::filesystem::path& input_path,
                        std::string* error_reason = nullptr) {
  namespace fs = std::filesystem;

  const auto set_error = [&](std::string message) {
    if (error_reason != nullptr) {
      *error_reason = std::move(message);
    }
  };

  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }
  if (ec) {
    set_error("не удалось проверить путь \"" + input_path.string() +
              "\": " + ec.message());
    return std::nullopt;
  }

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) {
    set_error("не удалось получить текущий каталог: " + ec.message());
    return std::nullopt;
  }

  const fs::path relative = input_path.is_absolute()
                                ? input_path.relative_path()
                                : input_path;

  for (const fs::path& component_path : relative) {
    const std::string component = component_path.string();
    if (component.empty() || component == ".") continue;

    if (component == "..") {
      current = current.parent_path();
      continue;
    }

    const fs::path direct_candidate = current / component_path;
    ec.clear();
    if (fs::exists(direct_candidate, ec) && !ec) {
      current = direct_candidate;
      continue;
    }
    if (ec) {
      set_error("ошибка доступа к \"" + direct_candidate.string() +
                "\": " + ec.message());
      return std::nullopt;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec) {
      set_error(ec ? "ошибка доступа к \"" + current.string() +
                         "\": " + ec.message()
                   : "каталог \"" + current.string() + "\" не существует");
      return std::nullopt;
    }
    if (!fs::is_directory(current, ec) || ec) {
      set_error(ec ? "не удалось открыть каталог \"" + current.string() +
                         "\": " + ec.message()
                   : "путь \"" + current.string() +
                         "\" не является каталогом");
      return std::nullopt;
    }

    const std::string component_lower = to_lower(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;

      if (to_lower(entry.path().filename().string()) == component_lower) {
        current = entry.path();
        matched = true;
        break;
      }
    }

    if (ec) {
      set_error("не удалось прочитать каталог \"" + current.string() +
                "\": " + ec.message());
      return std::nullopt;
    }
    if (!matched) {
      set_error("компонент пути \"" + component + "\" не найден");
      return std::nullopt;
    }
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) {
    return current;
  }
  if (ec) {
    set_error("не удалось проверить разрешенный путь \"" + current.string() +
              "\": " + ec.message());
  }
  return std::nullopt;
}

}  // namespace PathUtils
