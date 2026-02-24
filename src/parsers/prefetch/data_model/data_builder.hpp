/// @file data_builder.hpp
/// @brief Реализация паттерна "Строитель" для объектов Prefetch-данных

#pragma once

#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include "errors/prefetch_exception.hpp"
#include "parsers/prefetch/metadata/file_metric.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"
#include "data_storage.hpp"
#include "idata.hpp"

namespace PrefetchAnalysis {

/// @class PrefetchDataBuilder
/// @brief Реализация паттерна "Строитель" для создания объектов PrefetchData
/// @details Обеспечивает:
///    - Пошаговое конструирование объекта
///    - Автоматическую валидацию данных на каждом этапе
///    - Гибкое добавление элементов коллекций
///    - Гарантии безопасности исключений
/// @note Все методы установки значений не меняют состояние объекта при
/// исключениях
class PrefetchDataBuilder {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор по умолчанию
  PrefetchDataBuilder() = default;

  /// @brief Деструктор по умолчанию
  ~PrefetchDataBuilder() noexcept = default;

  /// @}

  /// @name Методы установки основных параметров
  /// @{

  /// @brief Установка имени исполняемого файла
  /// @param[in] executable_name Имя файла в формате "NAME.EXE-XXXXXXXX.pf"
  /// @return Ссылка на текущий объект строителя
  /// @exception InvalidExecutableNameException Если имя не соответствует
  /// формату
  PrefetchDataBuilder& setExecutableName(
      const std::string& executable_name) noexcept;

  /// @brief Установка хэша Prefetch-файла
  /// @param[in] prefetch_hash 32-битный хеш пути исполняемого файла
  /// @return Ссылка на текущий объект строителя
  /// @exception InvalidPrefetchHashException Если хэш равен 0
  PrefetchDataBuilder& setPrefetchHash(uint32_t prefetch_hash) noexcept;

  /// @brief Установка счетчика запусков
  /// @param[in] run_count Количество зарегистрированных запусков
  /// @return Ссылка на текущий объект строителя
  PrefetchDataBuilder& setRunCount(uint32_t run_count) noexcept;

  /// @brief Установка версии формата
  /// @param[in] version Номер версии формата (10,17,23,26,30)
  /// @return Ссылка на текущий объект строителя
  /// @exception InvalidVersionException Если версия неизвестна
  PrefetchDataBuilder& setFormatVersion(uint8_t version) noexcept;

  /// @brief Установка времени последнего запуска
  /// @param[in] last_run_time Время в формате FILETIME (100-нс интервалы)
  /// @return Ссылка на текущий объект строителя
  /// @exception InvalidRunTimeException Если время равно 0 или за пределами
  /// 1601-2500 гг.
  PrefetchDataBuilder& setLastRunTime(uint64_t last_run_time) noexcept;

  /// @}

  /// @name Методы добавления элементов коллекций
  /// @{

  /// @brief Добавление времени запуска
  /// @param[in] run_time Время запуска в формате FILETIME
  /// @return Ссылка на текущий объект строителя
  PrefetchDataBuilder& addRunTime(uint64_t run_time) noexcept;

  /// @brief Добавление информации о томе
  /// @param[in] vol Данные о томе
  /// @return Ссылка на текущий объект строителя
  PrefetchDataBuilder& addVolume(VolumeInfo vol) noexcept;

  /// @brief Добавление файловой метрики
  /// @param[in] metric Данные о доступе к файлу
  /// @return Ссылка на текущий объект строителя
  PrefetchDataBuilder& addMetric(FileMetric metric) noexcept;

  /// @}

  /// @name Финальная сборка объекта
  /// @{

  /// @brief Построение объекта PrefetchData
  /// @return Указатель на готовый объект
  /// @exception PrefetchDataException Если обязательные параметры не
  /// установлены
  /// @details Выполняет комплексную валидацию всех данных перед созданием
  /// объекта
  [[nodiscard]] std::unique_ptr<IPrefetchData> build();

  /// @}

 private:
  /// @name Внутренние методы валидации
  /// @{

  /// @brief Валидация основных параметров
  /// @exception InvalidExecutableNameException Некорректное имя файла
  /// @exception InvalidPrefetchHashException Некорректный хэш
  /// @exception InvalidVersionException Неподдерживаемая версия формата
  void validateCoreData() const;

  /// @brief Валидация временных меток запусков
  void validateRunTimes() const;

  /// @brief Валидация информации о томах
  void validateVolumes() const;

  /// @brief Валидация файловых метрик
  void validateMetric() const;

  /// @}

  PrefetchDataStorage storage_;           ///< Основное хранилище данных
  std::vector<VolumeInfo> volume_cache_;  ///< Кэш для информации о томах
  std::vector<FileMetric> metric_cache_;  ///< Кэш для файловых метрик
};

}
