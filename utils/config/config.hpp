/// @file config.hpp
/// @brief Класс для чтения конфигурационных файлов в формате INI

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "../../core/exceptions/config_exception.hpp"
#include "simple_ini.hpp"

/// @class Config
/// @brief Класс для чтения конфигурационных файлов в формате INI
class Config {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор
  /// @param filename Путь к INI-файлу конфигурации
  /// @param useMultiKey Поддержка нескольких ключей с одинаковым именем
  /// @param useMultiLine Поддержка многострочных значений
  /// @throw ConfigFileException Ошибка чтения файла
  explicit Config(std::string filename, bool useMultiKey = false,
                  bool useMultiLine = false);

  /// @brief Конструктор копирования
  Config(const Config& other) noexcept;

  /// @}

  /// @name Методы доступа к конфигурационным параметрам
  /// @{

  /// @brief Перезагружает конфигурацию из файла
  /// @throw ConfigFileException Ошибка чтения файла
  void reload() const;

  /// @brief Получение строкового параметра
  /// @param section Секция в INI-файле
  /// @param key Ключ параметра
  /// @param defaultValue Значение по умолчанию
  /// @return Значение параметра или defaultValue
  /// @throw ConfigValueException Если значение не может быть прочитано
  [[nodiscard]] std::string getString(
      const std::string& section, const std::string& key,
      const std::string& defaultValue = "") const;

  /// @brief Получение целочисленного параметра
  /// @param section Секция в INI-файле
  /// @param key Ключ параметра
  /// @param defaultValue Значение по умолчанию
  /// @return Значение параметра или defaultValue
  /// @throw ConfigValueException Если значение не может быть преобразовано в
  /// число
  [[nodiscard]] int getInt(const std::string& section, const std::string& key,
                           int defaultValue = 0) const;

  /// @brief Получение параметра с плавающей точкой
  /// @param section Секция в INI-файле
  /// @param key Ключ параметра
  /// @param defaultValue Значение по умолчанию
  /// @return Значение параметра или defaultValue
  /// @throw ConfigValueException Если значение не может быть преобразовано в
  /// число
  [[nodiscard]] double getDouble(const std::string& section,
                                 const std::string& key,
                                 double defaultValue = 0.0) const;

  /// @brief Получение булева параметра
  /// @param section Секция в INI-файле
  /// @param key Ключ параметра
  /// @param defaultValue Значение по умолчанию
  /// @return Значение параметра или defaultValue
  /// @throw ConfigValueException Если значение не может быть преобразовано в
  /// bool
  ///
  /// Поддерживаемые форматы значений:
  /// - true/false
  /// - yes/no
  /// - on/off
  /// - 1/0
  ///
  /// Регистр символов не учитывается.
  [[nodiscard]] bool getBool(const std::string& section, const std::string& key,
                             bool defaultValue = false) const;

  /// @}

  /// @name Методы проверки и получения данных
  /// @{

  /// @brief Получение всех значений для секции
  /// @param section Секция в INI-файле
  /// @return Вектор пар ключ-значение
  /// @throw ConfigValueException Если секция не существует
  [[nodiscard]] std::vector<std::pair<std::string, std::string>> getAllValues(
      const std::string& section) const;

  /// @brief Проверка существования секции
  /// @param section Имя секции
  /// @return true если секция существует
  [[nodiscard]] bool hasSection(const std::string& section) const noexcept;

  /// @brief Проверка существования ключа в секции
  /// @param section Секция
  /// @param key Ключ
  /// @return true если ключ существует
  [[nodiscard]] bool hasKey(const std::string& section,
                            const std::string& key) const noexcept;

  std::vector<std::string> getKeysInSection(
      const std::string& section_name) const;

  /// @}

 private:
  std::shared_ptr<CSimpleIniA>
      ini_;               ///< Разделяемый объект SimpleIni для работы с INI
  std::string filename_;  ///< Путь к конфигурационному файлу
  bool useMultiKey_;      ///< Поддержка нескольких ключей
  bool useMultiLine_;     ///< Поддержка многострочных значений
  std::map<std::string, std::map<std::string, std::string>> data_;
};
