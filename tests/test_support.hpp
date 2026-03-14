/// @file test_support.hpp
/// @brief Общие тестовые утилиты для работы с временными файлами и командами.

#pragma once

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace TestSupport {

/// @class TempDir
/// @brief RAII-обёртка для временного каталога теста.
class TempDir {
 public:
  /// @brief Создаёт/очищает каталог `program_traces_<name>` во временной директории.
  explicit TempDir(std::string name) {
    path_ = std::filesystem::temp_directory_path() /
            ("program_traces_" + std::move(name));
    std::filesystem::remove_all(path_);
    std::filesystem::create_directories(path_);
  }

  /// @brief Удаляет временный каталог вместе с содержимым.
  ~TempDir() { std::filesystem::remove_all(path_); }

  /// @brief Возвращает путь к каталогу.
 const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;  ///< Путь к временному каталогу теста.
};

/// @brief Записывает текстовый файл, предварительно создавая родительские каталоги.
inline void writeTextFile(const std::filesystem::path& path,
                          const std::string& content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("failed to open file for writing: " + path.string());
  }
  file << content;
}

/// @brief Записывает бинарный файл, предварительно создавая родительские каталоги.
inline void writeBinaryFile(const std::filesystem::path& path,
                            const std::vector<uint8_t>& bytes) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("failed to open file for writing: " + path.string());
  }
  file.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
}

/// @brief Читает файл целиком как текст.
inline std::string readTextFile(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

/// @brief Выполняет shell-команду и возвращает stdout.
inline std::string runCommand(const std::string& command) {
  std::string output;
  std::array<char, 256> buffer{};
  FILE* pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return output;
  }
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output += buffer.data();
  }
  pclose(pipe);
  return output;
}

}  // namespace TestSupport
