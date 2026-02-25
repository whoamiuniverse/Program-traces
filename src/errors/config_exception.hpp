/// @file config_exception.hpp
/// @brief Заголовочный файл с определениями исключений для работы с
/// конфигурацией

#pragma once

#include "errors/app_exception.hpp"

#include <string>

/// @class ConfigException
/// @brief Базовое исключение для всех ошибок, связанных с конфигурацией
/// @details Используется как базовый класс для специализированных
/// исключений конфигурации.
class ConfigException : public AppException {
 public:
  /// @brief Конструктор исключения
  /// @param message Сообщение об ошибке
  explicit ConfigException(const std::string& message)
      : AppException(message) {}
};

/// @class ConfigFileException
/// @brief Исключение для ошибок загрузки конфигурационных файлов
/// @details Возникает при проблемах с чтением или разбором конфигурационного
/// файла
class ConfigFileException : public ConfigException {
 public:
  /// @brief Конструктор исключения
  /// @param filename Имя файла, при загрузке которого произошла ошибка
  explicit ConfigFileException(const std::string& filename)
      : ConfigException("Ошибка загрузки конфигурационного файла: " + filename),
        filename_(filename) {}

  /// @brief Получить имя файла, вызвавшего ошибку
  /// @return Константная ссылка на имя файла
  /// @note Метод не бросает исключений
  [[nodiscard]] const std::string& getFilename() const noexcept {
    return filename_;
  }

 private:
  std::string filename_;  ///< Имя файла, вызвавшего ошибку
};

/// @class ConfigValueException
/// @brief Исключение для ошибок парсинга значений конфигурации
/// @details Возникает при невозможности преобразовать значение параметра
/// в требуемый тип или при других ошибках валидации
class ConfigValueException : public ConfigException {
 public:
  /// @brief Конструктор исключения
  /// @param section Секция конфигурации, в которой произошла ошибка
  /// @param key Ключ параметра, вызвавшего ошибку
  /// @param message Дополнительное сообщение об ошибке
  ConfigValueException(const std::string& section, const std::string& key,
                       const std::string& message)
      : ConfigException("Ошибка в секции [" + section + "], ключ '" + key +
                        "': " + message),
        section_(section),
        key_(key) {}

  /// @brief Получить имя секции, в которой произошла ошибка
  /// @return Константная ссылка на имя секции
  /// @note Метод не бросает исключений
  [[nodiscard]] const std::string& getSection() const noexcept {
    return section_;
  }

  /// @brief Получить ключ параметра, вызвавшего ошибку
  /// @return Константная ссылка на ключ параметра
  /// @note Метод не бросает исключений
  [[nodiscard]] const std::string& getKey() const noexcept { return key_; }

 private:
  std::string section_;  ///< Имя секции конфигурации
  std::string key_;      ///< Ключ параметра
};
