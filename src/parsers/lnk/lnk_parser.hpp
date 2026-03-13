/// @file lnk_parser.hpp
/// @brief Минимальный структурный парсер Windows Shell Link (LNK).

#pragma once

#include <optional>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

/// @struct LnkInfo
/// @brief Извлеченные структурные поля LNK-файла.
struct LnkInfo {
  std::string target_path;
  std::string relative_path;
  std::string working_dir;
  std::string arguments;
  std::string creation_time;
  std::string access_time;
  std::string write_time;
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
