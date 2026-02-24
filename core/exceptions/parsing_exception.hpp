/// @file parsing_exception.hpp
/// @brief Исключения для обработки ошибок парсинга Prefetch-файлов

#pragma once

#include <stdexcept>
#include <string>

/// @class InitLibError
/// @brief Исключение для ошибок инициализации библиотек
/// @details Генерируется при невозможности инициализировать необходимые
/// библиотеки для работы с Prefetch-файлами
class InitLibError : public std::runtime_error {
 public:
  /// @brief Конструктор исключения
  /// @param[in] lib_name Название библиотеки, вызвавшей ошибку
  explicit InitLibError(const std::string& lib_name)
      : std::runtime_error("Ошибка инициализации библиотеки " + lib_name) {}
};

/// @class ParsingException
/// @brief Базовое исключение для ошибок парсинга
/// @details Служит основой для всех специализированных исключений парсинга
class ParsingException : public std::runtime_error {
 public:
  /// @brief Конструктор исключения
  /// @param[in] message Описание ошибки
  explicit ParsingException(const std::string& message)
      : std::runtime_error(message) {}

  /// @brief Виртуальный деструктор
  ~ParsingException() noexcept override = default;
};

/// @class FileOpenException
/// @brief Исключение для ошибок открытия файлов
/// @details Генерируется при:
///    - Отсутствии файла по указанному пути
///    - Недостаточных правах доступа
///    - Физических повреждениях носителя
class FileOpenException : public ParsingException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] file_path Путь к проблемному файлу
  explicit FileOpenException(const std::string& file_path)
      : ParsingException("Не удалось открыть файл \"" + file_path + "\""),
        file_path_(file_path) {}

  /// @brief Получить путь к проблемному файлу
  /// @return Путь к файлу
  [[nodiscard]] std::string getFilePath() const noexcept { return file_path_; }

 private:
  std::string file_path_;
};

/// @class DataReadException
/// @brief Исключение для ошибок чтения данных
/// @details Генерируется при:
///    - Ошибках ввода-вывода
///    - Неожиданном конце файла
///    - Повреждении данных
class DataReadException : public ParsingException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] context Контекст ошибки
  explicit DataReadException(const std::string& context)
      : ParsingException("Ошибка чтения данных: " + context) {}
};

/// @class InvalidTimestampException
/// @brief Исключение для некорректных временных меток
/// @details Генерируется при:
///    - Значениях времени до эпохи UNIX (01.01.1970)
///    - Значениях, превышающих разумные пределы (> 2500 год)
///    - Нулевых значениях времени
class InvalidTimestampException : public ParsingException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] timestamp Некорректное значение времени
  /// @param[in] details Дополнительные детали
  explicit InvalidTimestampException(const uint64_t timestamp,
                                     const std::string& details)
      : ParsingException("Некорректная временная метка 0x" + to_hex(timestamp) +
                         ": " + details),
        timestamp_(timestamp) {}

  /// @brief Получить некорректное значение времени
  /// @return Значение временной метки
  [[nodiscard]] uint64_t getInvalidTimestamp() const noexcept { return timestamp_; }

 private:
  static std::string to_hex(const uint64_t value) {
    char buffer[17];
    snprintf(buffer, sizeof(buffer), "%016lX", value);
    return buffer;
  }

  uint64_t timestamp_;
};

/// @class InvalidVolumeException
/// @brief Исключение для ошибок валидации томов
/// @details Генерируется при:
///    - Некорректных путях устройств
///    - Нулевых серийных номерах
///    - Невалидных временах создания
class InvalidVolumeException : public ParsingException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] device_path Путь к устройству
  /// @param[in] details Детали ошибки
  explicit InvalidVolumeException(const std::string& device_path,
                                  const std::string& details)
      : ParsingException("Ошибка тома '" + device_path + "': " + details) {}
};

/// @class InvalidFileMetricException
/// @brief Исключение для ошибок валидации файловых метрик
/// @details Генерируется при:
///    - Некорректных путях файлов
///    - Нулевых MFT-ссылках
///    - Невалидных временах доступа
class InvalidFileMetricException : public ParsingException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] filename Имя файла
  /// @param[in] details Детали ошибки
  explicit InvalidFileMetricException(const std::string& filename,
                                      const std::string& details)
      : ParsingException("Ошибка метрики файла '" + filename +
                         "': " + details) {}
};
