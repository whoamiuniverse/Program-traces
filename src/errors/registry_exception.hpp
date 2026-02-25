/// @file registry_exception.hpp
/// @brief Исключения для работы с реестром Windows

#pragma once

#include "errors/app_exception.hpp"

#include <fmt/format.h>

#include <string>

namespace RegistryAnalysis {

/// @class RegistryException
/// @brief Базовый класс для ошибок, связанных с реестром
/// @details Является базовым классом для всех исключений при работе с реестром
class RegistryException : public AppException {
 public:
  /// @brief Конструктор базового исключения
  /// @param message Человекочитаемое описание ошибки
  explicit RegistryException(const std::string& message)
      : AppException(message) {}
};

/// @class RootKeyError
/// @brief Ошибка доступа к корневому разделу реестра
class RootKeyError : public RegistryException {
 public:
  /// @brief Формирует ошибку доступа к корневому ключу
  /// @param details Дополнительный технический контекст
  explicit RootKeyError(const std::string& details = "")
      : RegistryException("Ошибка доступа к корневому разделу реестра" +
                          (details.empty() ? "" : ": " + details)) {}
};

/// @class KeyNotFoundError
/// @brief Ошибка: подраздел реестра не найден
class KeyNotFoundError : public RegistryException {
 public:
  /// @brief Формирует ошибку отсутствующего раздела реестра
  /// @param name Имя искомого раздела
  /// @param path Путь, в котором выполнялся поиск
  explicit KeyNotFoundError(const std::string& name,
                            const std::string& path = "")
      : RegistryException("Подраздел реестра \"" + name + "\" не найден" +
                          (path.empty() ? "" : " по пути: " + path)) {}
};

/// @class ValueNotFoundError
/// @brief Ошибка: значение в реестре не найдено
class ValueNotFoundError : public RegistryException {
 public:
  /// @brief Формирует ошибку отсутствующего значения реестра
  /// @param name Имя искомого значения
  /// @param key_path Раздел, внутри которого выполнялся поиск
  explicit ValueNotFoundError(const std::string& name,
                              const std::string& key_path = "")
      : RegistryException("Значение \"" + name + "\" не найдено" +
                          (key_path.empty() ? "" : " в разделе: " + key_path)) {
  }
};

/// @class BinaryDataReadError
/// @brief Ошибка чтения бинарных данных из реестра
class BinaryDataReadError : public RegistryException {
 public:
  /// @brief Формирует ошибку чтения бинарного payload
  /// @param details Дополнительные сведения о причине ошибки
  explicit BinaryDataReadError(const std::string& details = "")
      : RegistryException("Ошибка чтения бинарных данных" +
                          (details.empty() ? "" : ": " + details)) {}
};

/// @class InvalidType
/// @brief Ошибка неподдерживаемого или некорректного типа значения
class InvalidType : public RegistryException {
 public:
  /// @brief Формирует ошибку неверного типа данных
  /// @param type Числовой код типа, полученный из источника данных
  explicit InvalidType(const uint32_t type)
      : RegistryException(
            "Некорректный тип данных реестра (в числовом представлении): " +
            std::to_string(type)) {}
};

/// @class InvalidValueAccess
/// @brief Ошибка доступа к значению несоответствующего типа
class InvalidValueAccess : public RegistryException {
 public:
  /// @brief Формирует ошибку доступа к значению через неверный accessor
  /// @param expected_type Ожидаемый тип значения
  /// @param actual_type Фактический тип значения
  /// @param value_name Имя значения для контекста диагностики
  explicit InvalidValueAccess(const std::string& expected_type,
                              const std::string& actual_type,
                              const std::string& value_name = "")
      : RegistryException(
            fmt::format("Некорректный доступ к значению \"{}\": "
                        "ожидался тип \"{}\", фактический тип \"{}\"",
                        value_name, expected_type, actual_type)) {}
};

/// @class ValueConversionError
/// @brief Ошибка преобразования значения реестра
class ValueConversionError : public RegistryException {
 public:
  /// @brief Формирует ошибку преобразования данных значения
  /// @param value_name Имя значения реестра
  /// @param details Детали неуспешного преобразования
  explicit ValueConversionError(const std::string& value_name,
                                const std::string& details)
      : RegistryException(
            fmt::format("Ошибка преобразования значения \"{}\": \"{}\"",
                        value_name, details)) {}
};

/// @class UnsupportedTypeError
/// @brief Ошибка неподдерживаемого типа значения реестра
class UnsupportedTypeError : public RegistryException {
 public:
  /// @brief Формирует ошибку неподдерживаемого типа реестра
  /// @param type Числовой код типа из источника
  explicit UnsupportedTypeError(uint32_t type)
      : RegistryException(
            fmt::format("Неподдерживаемый тип данных реестра: 0x{:X}", type)) {}
};

/// @class TypeCompatibilityError
/// @brief Ошибка несовместимости типа данных и значения
class TypeCompatibilityError : public RegistryException {
 public:
  /// @brief Формирует ошибку несовместимости ожидаемого и фактического типа
  /// @param expected_type Тип, который ожидал вызывающий код
  /// @param actual_type Тип, который реально содержит значение
  /// @param value_name Имя значения, для которого выполнялась операция
  explicit TypeCompatibilityError(const std::string& expected_type,
                                  const std::string& actual_type,
                                  const std::string& value_name = "")
      : RegistryException(
            fmt::format("Несовместимость типов для значения "
                        "\"{}\": ожидался \"{}\", фактический \"{}\"",
                        value_name, expected_type, actual_type)) {}
};

/// @class RegistryNotOpenError
/// @brief Ошибка доступа к неоткрытому реестру
class RegistryNotOpenError : public RegistryException {
 public:
  /// @brief Формирует ошибку доступа к неинициализированному парсеру
  /// @param details Контекст, в котором обнаружен некорректный доступ
  explicit RegistryNotOpenError(const std::string& details)
      : RegistryException(fmt::format(
            "Ошибка доступа к неоткрытому реестру: \"{}\"", details)) {}
};

/// @class InvalidPathError
/// @brief Ошибка неверного пути в реестре
class InvalidPathError : public RegistryException {
 public:
  /// @brief Формирует ошибку некорректного пути реестра
  /// @param path Путь, не прошедший валидацию
  explicit InvalidPathError(const std::string& path)
      : RegistryException(
            fmt::format("Неверный путь в реестре: \"{}\"", path)) {}
};

}
