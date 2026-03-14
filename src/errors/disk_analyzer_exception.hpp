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
  /// @brief Создаёт базовое исключение анализа диска.
  /// @param message Описание ошибки.
  explicit DiskAnalyzerException(const std::string& message)
      : AppException(message) {}
};

/// @class InvalidDiskRootException
/// @brief Некорректный аргумент/путь корня анализируемого диска.
class InvalidDiskRootException : public DiskAnalyzerException {
 public:
  /// @brief Создаёт исключение невалидного корня диска.
  /// @param disk_root Значение аргумента корня диска.
  /// @param details Дополнительные детали ошибки.
  InvalidDiskRootException(const std::string& disk_root,
                           const std::string& details)
      : DiskAnalyzerException("Некорректный корень анализа \"" + disk_root +
                              "\": " + details),
        disk_root_(disk_root) {}

  /// @brief Возвращает исходное значение некорректного корня.
  /// @return Ссылка на путь корня диска.
  [[nodiscard]] const std::string& diskRoot() const noexcept { return disk_root_; }

 private:
  std::string disk_root_;  ///< Некорректный путь корня диска.
};

/// @class DiskNotMountedException
/// @brief Устройство задано, но не смонтировано как файловая система.
class DiskNotMountedException : public DiskAnalyzerException {
 public:
  /// @brief Создаёт исключение для не смонтированного устройства.
  /// @param device_path Путь устройства (например `/dev/diskXsY`).
  explicit DiskNotMountedException(const std::string& device_path)
      : DiskAnalyzerException("Устройство \"" + device_path +
                              "\" не смонтировано"),
        device_path_(device_path) {}

  /// @brief Возвращает путь проблемного устройства.
  /// @return Ссылка на путь устройства.
  [[nodiscard]] const std::string& devicePath() const noexcept {
    return device_path_;
  }

 private:
  std::string device_path_;  ///< Путь устройства без точки монтирования.
};

/// @class RegistryHiveValidationException
/// @brief В корне диска не найден ни один ожидаемый registry hive.
class RegistryHiveValidationException : public DiskAnalyzerException {
 public:
  /// @brief Создаёт исключение отсутствия ожидаемых hive-файлов.
  /// @param disk_root Корень диска, где не найден hive.
  explicit RegistryHiveValidationException(const std::string& disk_root)
      : DiskAnalyzerException("В выбранном корне не найден hive-файл Windows: \"" +
                              disk_root + "\""),
        disk_root_(disk_root) {}

  /// @brief Возвращает путь корня, не прошедшего проверку.
  /// @return Ссылка на путь корня диска.
  [[nodiscard]] const std::string& diskRoot() const noexcept { return disk_root_; }

 private:
  std::string disk_root_;  ///< Корень диска без найденных hive-файлов.
};

/// @class WindowsVolumeSelectionException
/// @brief Автоматический/интерактивный выбор Windows-тома завершился ошибкой.
class WindowsVolumeSelectionException : public DiskAnalyzerException {
 public:
  /// @brief Создаёт исключение ошибки выбора тома Windows.
  /// @param details Подробности причины ошибки.
  explicit WindowsVolumeSelectionException(const std::string& details)
      : DiskAnalyzerException("Не удалось выбрать раздел Windows: " + details) {}
};

/// @class OutputDirectoryException
/// @brief Невозможно создать каталог для выходного CSV-файла.
class OutputDirectoryException : public DiskAnalyzerException {
 public:
  /// @brief Создаёт исключение ошибки подготовки выходного каталога.
  /// @param output_path Выходной путь файла/каталога.
  /// @param details Подробности ошибки файловой системы.
  OutputDirectoryException(const std::string& output_path,
                           const std::string& details)
      : DiskAnalyzerException("Не удалось подготовить выходной путь \"" +
                              output_path + "\": " + details),
        output_path_(output_path) {}

  /// @brief Возвращает проблемный выходной путь.
  /// @return Ссылка на выходной путь.
  [[nodiscard]] const std::string& outputPath() const noexcept {
    return output_path_;
  }

 private:
  std::string output_path_;  ///< Путь, для которого не удалось создать каталог.
};

}  // namespace WindowsDiskAnalysis
