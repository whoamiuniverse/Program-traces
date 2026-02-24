/// @file ios_detection.hpp
/// @brief Интерфейс для определения версии Windows на основе данных реестра

#pragma once

#include "os_info.hpp"

namespace WindowsVersion {

/// @class IOSDetection
/// @brief Интерфейс для определения версии Windows на основе данных реестра
class IOSDetection {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Виртуальный деструктор
  virtual ~IOSDetection() = default;

  /// @}

  /// @name Методы определения версии ОС
  /// @{

  /// @brief Определяет информацию о версии Windows
  /// @return Структура OSInfo с данными об операционной системе
  [[nodiscard]] virtual OSInfo detect() = 0;

  /// @}
};

}
