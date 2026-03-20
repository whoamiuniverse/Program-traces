/// @file lnk_parser.hpp
/// @brief Минимальный структурный парсер Windows Shell Link (LNK).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

/// @struct LnkInfo
/// @brief Извлеченные структурные поля LNK-файла.
struct LnkInfo {
  std::string target_path;    ///< Целевой путь, на который указывает ярлык.
  std::string relative_path;  ///< Относительный путь из StringData-блока LNK.
  std::string working_dir;    ///< Рабочий каталог запуска ярлыка.
  std::string arguments;      ///< Аргументы командной строки, сохранённые в ярлыке.
  std::string creation_time;  ///< Время создания цели (FILETIME -> UTC string).
  std::string access_time;    ///< Время последнего доступа к цели.
  std::string write_time;     ///< Время последней модификации цели.
};

/// @brief Парсит LNK-файл на диске.
/// @param path Абсолютный путь к `.lnk`.
/// @return Разобранная структура либо `std::nullopt`.
std::optional<LnkInfo> parseLnkFile(const std::string& path);

/// @brief Парсит LNK из уже загруженных байтов.
/// @param data Содержимое `.lnk`.
/// @return Разобранная структура либо `std::nullopt`.
std::optional<LnkInfo> parseLnkBytes(const std::vector<uint8_t>& data);

}  // namespace WindowsDiskAnalysis
