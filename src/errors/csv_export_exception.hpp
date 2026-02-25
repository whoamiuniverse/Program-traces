/// @file csv_export_exception.hpp
/// @brief Исключения для ошибок экспорта в CSV

#pragma once

#include "errors/app_exception.hpp"

#include <string>

namespace WindowsDiskAnalysis {

/// @class CsvExportException
/// @brief Базовое исключение для ошибок экспорта в CSV
/// @details Используется как базовый класс для всех специализированных
/// исключений модуля экспорта.
class CsvExportException : public AppException {
 public:
  /// @brief Конструктор исключения
  /// @param message Сообщение об ошибке
  explicit CsvExportException(const std::string& message)
      : AppException(message) {}
};

/// @class FileOpenException
/// @brief Исключение при ошибках открытия файла
/// @details Генерируется когда невозможно открыть файл для записи CSV данных.
/// Наследует CsvExportException и добавляет контекст имени файла
class FileOpenException : public CsvExportException {
 public:
  /// @brief Конструктор исключения
  /// @param filename Имя файла который не удалось открыть
  explicit FileOpenException(const std::string& filename)
      : CsvExportException("Ошибка открытия файла: " + filename) {}
};

/// @class DataFormatException
/// @brief Исключение при ошибках формата данных
/// @details Генерируется при обнаружении некорректных или неконсистентных
/// данных, которые невозможно экспортировать в CSV. Содержит имя проблемного
/// поля
class DataFormatException : public CsvExportException {
 public:
  /// @brief Конструктор исключения
  /// @param field Имя поля с некорректными данными
  explicit DataFormatException(const std::string& field)
      : CsvExportException("Ошибка формата данных в поле: " + field) {}
};

}
