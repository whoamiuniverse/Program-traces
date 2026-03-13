/// @file compound_file.hpp
/// @brief Минимальный reader для Compound File Binary Format (OLE2).

#pragma once

#include <optional>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis::CompoundFile {

/// @struct Stream
/// @brief Один stream внутри Compound File.
struct Stream {
  std::string name;
  std::vector<uint8_t> data;
};

/// @brief Читает и перечисляет stream'ы Compound File.
/// @param path Путь к `.automaticDestinations-ms` или другому OLE2 контейнеру.
/// @return Вектор stream'ов либо `std::nullopt`, если файл невалиден.
std::optional<std::vector<Stream>> readStreams(const std::string& path);

/// @brief Парсит stream'ы Compound File из памяти.
/// @param bytes Содержимое OLE2 контейнера.
/// @return Вектор stream'ов либо `std::nullopt`, если данные невалидны.
std::optional<std::vector<Stream>> parseStreams(const std::vector<uint8_t>& bytes);

}  // namespace WindowsDiskAnalysis::CompoundFile
