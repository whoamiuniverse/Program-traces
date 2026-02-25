/// @file logger_exception.hpp
/// @brief Исключение при инициализации логгера

#pragma once

#include "errors/app_exception.hpp"

#include <string>

/// @class LoggerInitException
/// @brief Исключение при инициализации логгера
class LoggerInitException : public AppException {
 public:
  /// @brief Конструктор
  /// @param message Сообщение об ошибке
  explicit LoggerInitException(const std::string& message)
      : AppException(message) {}
};
