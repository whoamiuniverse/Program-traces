/// @file parser.hpp
/// @brief Парсер Prefetch-файлов Windows

#pragma once

#include <libscca.h>

#include <ctime>
#include <memory>
#include <string>

#include "errors/parsing_exception.hpp"
#include "iparser.hpp"

namespace PrefetchAnalysis {

/// @name Константы времени
/// @{

constexpr uint64_t FILETIME_EPOCH_DIFF =
    116444736000000000ULL;  ///< Разница между FILETIME и UNIX-эпохой
                            ///< (1601-1970)
constexpr uint64_t FILETIME_MAX_VALID =
    2650467744000000000ULL;  ///< Максимальное допустимое значение (01.01.2500)

/// @}

/// @class PrefetchParser
/// @brief Реализация парсера Prefetch-файлов с использованием libscca
/// @details Обеспечивает:
///   - Чтение и валидацию Prefetch-файлов
///   - Преобразование данных в объектную модель
///   - Обработку ошибок формата и данных
class PrefetchParser : public IPrefetchParser {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор
  /// @exception InitLibError Ошибка инициализации libscca
  PrefetchParser();

  /// @brief Деструктор
  ~PrefetchParser() noexcept override;

  /// @}

  /// @name Основной интерфейс
  /// @{

  /// @brief Парсинг Prefetch-файла
  /// @param[in] path Путь к файлу
  /// @return Указатель на объект с данными
  /// @exception FileOpenException Ошибка открытия файла
  /// @exception InvalidFormatException Некорректный формат файла
  /// @exception DataReadException Ошибка чтения данных
  [[nodiscard]] std::unique_ptr<IPrefetchData> parse(
      const std::string& path) const override;

  /// @}

 private:
  /// @name Методы парсинга
  /// @{

  /// @brief Парсинг основной информации
  /// @param[in] scca_handle Открытый дескриптор Prefetch-файла
  /// @param[in] builder Сборщик данных
  /// @exception DataReadException Ошибка чтения обязательных полей
  void parseBasicInfo(libscca_file_t* scca_handle,
                      PrefetchDataBuilder& builder) const;

  /// @brief Парсинг временных меток запусков
  /// @param[in] scca_handle Открытый дескриптор Prefetch-файла
  /// @param[in] builder Сборщик данных
  void parseRunTimes(libscca_file_t* scca_handle,
                     PrefetchDataBuilder& builder) const;

  /// @brief Парсинг информации о томах
  /// @param[in] scca_handle Открытый дескриптор Prefetch-файла
  /// @param[in] builder Сборщик данных
  /// @exception DataReadException Ошибка чтения информации о томах
  void parseVolumes(libscca_file_t* scca_handle,
                    PrefetchDataBuilder& builder) const;

  /// @brief Парсинг файловых метрик
  /// @param[in] scca_handle Открытый дескриптор Prefetch-файла
  /// @param[in] builder Сборщик данных
  /// @exception DataReadException Ошибка чтения метрик
  void parseMetrics(libscca_file_t* scca_handle,
                    PrefetchDataBuilder& builder) const;

  /// @}

  /// @name Вспомогательные методы
  /// @{

  /// @brief Конвертация FILETIME в UNIX-время
  /// @param[in] filetime Время в формате FILETIME
  /// @return Время в формате UNIX
  /// @exception InvalidTimestampException Некорректное значение времени
  static uint64_t convertFiletime(uint64_t filetime);

  /// @brief Преобразует объект ошибки libscca в текст
  /// @param error Указатель на ошибку libscca
  /// @return Сообщение об ошибке
  static std::string toLibsccaErrorMessage(libscca_error_t* error);

  /// @}
};

}
