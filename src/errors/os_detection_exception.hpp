/// @file os_detection_exception.hpp
/// @brief Исключения, возникающее при ошибках определения операционной системы

#pragma once

#include "errors/app_exception.hpp"

#include <string>

namespace WindowsVersion {

/// @class OSDetectionException
/// @brief Исключение, возникающее при ошибках определения операционной системы
class OSDetectionException : public AppException {
 public:
  /// @brief Конструктор исключения
  /// @param message Сообщение об ошибке
  explicit OSDetectionException(const std::string& message)
      : AppException(message) {}
};

}
