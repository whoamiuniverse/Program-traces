/// @file prefetch_exception.hpp
/// @brief Исключения для обработки данных Prefetch

#pragma once

#include "errors/app_exception.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace PrefetchAnalysis {

/// @class PrefetchDataException
/// @brief Базовое исключение для ошибок обработки данных Prefetch
/// @details Служит основой для всех специализированных исключений в модуле
/// анализа Prefetch-файлов.
class PrefetchDataException : public AppException {
 public:
  /// @brief Конструктор базового исключения
  /// @param[in] message Описание ошибки
  explicit PrefetchDataException(const std::string& message)
      : AppException(message) {}
};

/// @class InvalidExecutableNameException
/// @brief Исключение для некорректного имени исполняемого файла
/// @details Генерируется при следующих условиях:
///    - Пустое имя файла
///    - Наличие запрещенных символов в имени
///    - Превышение максимальной длины имени (260 символов)
///    - Несоответствие ожидаемому шаблону "NAME.EXE-XXXXXXXX.pf"
class InvalidExecutableNameException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] filename Некорректное имя файла
  explicit InvalidExecutableNameException(const std::string& filename)
      : PrefetchDataException("Некорректное имя исполняемого файла: " +
                              filename) {}
};

/// @class InvalidPrefetchHashException
/// @brief Исключение для некорректного хэша Prefetch-файла
/// @details Генерируется при:
///    - Нулевом значении хэша (0x00000000)
///    - Специальных значениях, не соответствующих реальным хэшам
class InvalidPrefetchHashException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] hash_value Значение некорректного хэша
  explicit InvalidPrefetchHashException(uint32_t hash_value)
      : PrefetchDataException("Некорректный хэш Prefetch-файла: 0x" +
                              to_hex_string(hash_value)) {}

 private:
  /// @brief Преобразует хэш в строку формата `0xXXXXXXXX`
  /// @param value Числовое значение хэша
  /// @return Строковое HEX-представление
  static std::string to_hex_string(uint32_t value) {
    char buffer[11];
    snprintf(buffer, sizeof(buffer), "0x%08X", value);
    return buffer;
  }
};

/// @class InvalidVersionException
/// @brief Исключение для неподдерживаемых версий формата
/// @details Генерируется при:
///    - Версии меньше минимально поддерживаемой (10)
///    - Версии больше максимально известной (30)
///    - Неизвестных версиях формата
class InvalidVersionException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] version Некорректная версия формата
  explicit InvalidVersionException(const uint8_t version)
      : PrefetchDataException("Неподдерживаемая версия формата: " +
                              std::to_string(version)) {}
};

/// @class InvalidRunTimeException
/// @brief Исключение для некорректного времени запуска
/// @details Генерируется при:
///    - Нулевом значении времени (0)
///    - Значении за пределами допустимого диапазона (1601-2500 гг.)
///    - Для Win10+ при наличии массива времен запусков
class InvalidRunTimeException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] run_time Некорректное значение времени
  /// @param[in] message Дополнительное описание ошибки
  explicit InvalidRunTimeException(const uint64_t run_time,
                                   const std::string& message)
      : PrefetchDataException(message + ": " + std::to_string(run_time)),
        run_time_(run_time) {}

  /// @brief Возвращает некорректное значение времени
  /// @return Значение времени в формате FILETIME
  [[nodiscard]] uint64_t getInvalidTime() const noexcept { return run_time_; }

 private:
  uint64_t run_time_;  ///< Значение времени, которое не прошло валидацию
};

/// @class VolumeValidationException
/// @brief Исключение для ошибок валидации информации о томах
/// @details Генерируется при:
///    - Некорректном пути устройства
///    - Невалидном времени создания тома (0 или за пределами 1601-2500 гг.)
///    - Неподдерживаемом типе тома (не NTFS, FAT32)
class VolumeValidationException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] device_path Путь к устройству
  /// @param[in] message Детальное описание ошибки
  explicit VolumeValidationException(const std::string& device_path,
                                     const std::string& message)
      : PrefetchDataException("Ошибка валидации тома \"" + device_path +
                              "\": " + message) {}
};

/// @class MetricValidationException
/// @brief Исключение для ошибок валидации файловых метрик
/// @details Генерируется при:
///    - Некорректном пути к файлу (пустая строка, неформат)
///    - Невалидном времени доступа (0 или за пределами 1601-2500 гг.)
///    - Нулевой ссылке на MFT запись (0)
///    - Некорректном размере файла (0 для обычных файлов)
class MetricValidationException : public PrefetchDataException {
 public:
  /// @brief Конструктор исключения
  /// @param[in] filename Имя файла
  /// @param[in] message Детальное описание ошибки
  explicit MetricValidationException(const std::string& filename,
                                     const std::string& message)
      : PrefetchDataException("Ошибка валидации метрики \"" + filename +
                              "\": " + message) {}
};

}
