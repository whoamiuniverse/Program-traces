/// @file logger.hpp
/// @brief Модуль для управления глобальным логированием приложения

#pragma once

#include <spdlog/spdlog.h>

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

/// @class GlobalLogger
/// @brief Глобальный потокобезопасный логгер
class GlobalLogger {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор по умолчанию
  GlobalLogger() = delete;

  /// @brief Деструктор по умолчанию
  ~GlobalLogger() = delete;

  /// @}

  /// @name Методы для конфигурации логгера
  /// @{

  /// @brief Устанавливает путь для файлового лога
  /// @param path Путь к файлу лога
  /// @note Должен вызываться до первого использования логгера
  static void setLogPath(const std::string& path);

  /// @brief Возвращает глобальный экземпляр логгера
  /// @return Общий указатель на логгер
  /// @note Инициализирует логгер при первом вызове
  static std::shared_ptr<spdlog::logger> get();

 private:
  /// @brief Инициализирует систему логирования
  static void initialize();

  /// @}

  static std::string log_path_;                    ///< Путь к файлу лога
  static std::shared_ptr<spdlog::logger> logger_;  ///< Экземпляр логгера
  static std::mutex init_mutex_;  ///< Мьютекс для синхронизации инициализации
  static std::once_flag init_flag_;  ///< Флаг однократной инициализации
};
