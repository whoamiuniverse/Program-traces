/// @file disk_analyzer_exception.hpp
/// @brief Доменные исключения оркестратора анализа Windows-диска.

#pragma once

#include "errors/app_exception.hpp"

#include <string>

namespace WindowsDiskAnalysis {

/// @class DiskAnalyzerException
/// @brief Базовое исключение оркестратора анализа диска.
class DiskAnalyzerException : public AppException {
 public:
  explicit DiskAnalyzerException(const std::string& message)
      : AppException(message) {}
};

/// @class InvalidDiskRootException
/// @brief Некорректный аргумент/путь корня анализируемого диска.
class InvalidDiskRootException : public DiskAnalyzerException {
 public:
  InvalidDiskRootException(const std::string& disk_root,
                           const std::string& details)
      : DiskAnalyzerException("Некорректный корень анализа \"" + disk_root +
                              "\": " + details),
        disk_root_(disk_root) {}

  [[nodiscard]] const std::string& diskRoot() const noexcept { return disk_root_; }

 private:
  std::string disk_root_;
};

/// @class DiskNotMountedException
/// @brief Устройство задано, но не смонтировано как файловая система.
class DiskNotMountedException : public DiskAnalyzerException {
 public:
  explicit DiskNotMountedException(const std::string& device_path)
      : DiskAnalyzerException("Устройство \"" + device_path +
                              "\" не смонтировано"),
        device_path_(device_path) {}

  [[nodiscard]] const std::string& devicePath() const noexcept {
    return device_path_;
  }

 private:
  std::string device_path_;
};

/// @class RegistryHiveValidationException
/// @brief В корне диска не найден ни один ожидаемый registry hive.
class RegistryHiveValidationException : public DiskAnalyzerException {
 public:
  explicit RegistryHiveValidationException(const std::string& disk_root)
      : DiskAnalyzerException("В выбранном корне не найден hive-файл Windows: \"" +
                              disk_root + "\""),
        disk_root_(disk_root) {}

  [[nodiscard]] const std::string& diskRoot() const noexcept { return disk_root_; }

 private:
  std::string disk_root_;
};

/// @class WindowsVolumeSelectionException
/// @brief Автоматический/интерактивный выбор Windows-тома завершился ошибкой.
class WindowsVolumeSelectionException : public DiskAnalyzerException {
 public:
  explicit WindowsVolumeSelectionException(const std::string& details)
      : DiskAnalyzerException("Не удалось выбрать раздел Windows: " + details) {}
};

/// @class OutputDirectoryException
/// @brief Невозможно создать каталог для выходного CSV-файла.
class OutputDirectoryException : public DiskAnalyzerException {
 public:
  OutputDirectoryException(const std::string& output_path,
                           const std::string& details)
      : DiskAnalyzerException("Не удалось подготовить выходной путь \"" +
                              output_path + "\": " + details),
        output_path_(output_path) {}

  [[nodiscard]] const std::string& outputPath() const noexcept {
    return output_path_;
  }

 private:
  std::string output_path_;
};

}  // namespace WindowsDiskAnalysis
