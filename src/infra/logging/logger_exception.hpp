/// @file logger_exception.hpp
/// @brief Исключение при инициализации логгера

#pragma once

#include <stdexcept>
#include <string>

/// @class LoggerInitException
/// @brief Исключение при инициализации логгера
class LoggerInitException : public std::runtime_error {
 public:
  /// @brief Конструктор
  /// @param message Сообщение об ошибке
  explicit LoggerInitException(const std::string& message)
      : std::runtime_error(message) {}
};
