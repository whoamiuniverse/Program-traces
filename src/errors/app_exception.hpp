/// @file app_exception.hpp
/// @brief Базовое исключение приложения.

#pragma once

#include <exception>
#include <string>
#include <utility>

/// @class AppException
/// @brief Единый базовый тип исключений приложения.
/// @details Хранит человекочитаемое сообщение и предоставляет его через
/// `what()`. Используется как основа для всех доменных исключений проекта.
class AppException : public std::exception {
 public:
  /// @brief Конструктор базового исключения.
  /// @param message Сообщение об ошибке.
  explicit AppException(std::string message) : message_(std::move(message)) {}

  /// @brief Сообщение об ошибке в C-формате.
  /// @return Указатель на внутреннюю C-строку сообщения.
  [[nodiscard]] const char* what() const noexcept override {
    return message_.c_str();
  }

  /// @brief Сообщение об ошибке в std::string.
  /// @return Константная ссылка на сообщение.
 [[nodiscard]] const std::string& message() const noexcept { return message_; }

 private:
  std::string message_;  ///< Текстовое описание ошибки.
};
