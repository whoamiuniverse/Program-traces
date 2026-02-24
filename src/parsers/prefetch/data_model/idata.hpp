/// @file idata.hpp
/// @brief Интерфейс для доступа к данным Windows Prefetch-файлов

#pragma once

#include <string>
#include <vector>

#include "parsers/prefetch/metadata/file_metric.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"
#include "prefetch_versions.hpp"

namespace PrefetchAnalysis {

/// @class IPrefetchData
/// @brief Абстрактный интерфейс для работы с метаданными Prefetch-файлов
/// @details Определяет контракт для доступа к основным параметрам, временным
/// меткам, информации о томах и файловым метрикам Prefetch-файлов. Все методы
/// должны быть реализованы в классах-наследниках для конкретных версий формата
/// файлов
class IPrefetchData {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Виртуальный деструктор по умолчанию
  virtual ~IPrefetchData() noexcept = default;

  /// @}

  /// @name Основные параметры файла
  /// @{

  /// @brief Получить имя исполняемого файла
  /// @return Строка в формате "NAME.EXE-XXXXXXXX.pf", где XXXXXXXX - 8-значный
  /// хеш
  [[nodiscard]] virtual std::string getExecutableName() const noexcept = 0;

  /// @brief Получить 32-битный хеш Prefetch-файла
  /// @return Хеш-сумма, рассчитанная Windows при создании файла
  [[nodiscard]] virtual uint32_t getPrefetchHash() const noexcept = 0;

  /// @brief Получить количество зарегистрированных запусков
  /// @return Число запусков ≥ 0 (может отличаться от реального числа запусков)
  [[nodiscard]] virtual uint32_t getRunCount() const noexcept = 0;

  /// @}

  /// @name Временные характеристики
  /// @{

  /// @brief Получить список временных меток запусков
  /// @return Константная ссылка на вектор UNIX-времени (64 бита) в UTC
  [[nodiscard]] virtual const std::vector<uint64_t>& getRunTimes()
      const noexcept = 0;

  /// @brief Получить время последнего запуска
  /// @return UNIX-время последнего запуска (0 если данных нет)
  [[nodiscard]] virtual uint64_t getLastRunTime() const noexcept = 0;

  /// @}

  /// @name Информация о томах
  /// @{

  /// @brief Получить информацию о логических томах
  /// @return Константная ссылка на вектор VolumeInfo
  [[nodiscard]] virtual const std::vector<VolumeInfo>& getVolumes()
      const noexcept = 0;

  /// @brief Получить основной том приложения
  /// @return Объект VolumeInfo с данными основного тома
  /// @throw PrefetchDataException Если том не обнаружен
  [[nodiscard]] virtual VolumeInfo getMainVolume() const = 0;

  /// @}

  /// @name Файловые метрики
  /// @{

  /// @brief Получить все файловые метрики
  /// @return Константная ссылка на вектор FileMetric
  [[nodiscard]] virtual const std::vector<FileMetric>& getMetrics()
      const noexcept = 0;

  /// @brief Получить метрики только для DLL
  /// @return Вектор FileMetric для DLL-файлов
  /// @note Фильтрует метрики по расширению .dll
  [[nodiscard]] virtual std::vector<FileMetric> getDllMetrics() const = 0;

  /// @}

  /// @name Служебная информация
  /// @{

  /// @brief Получить версию формата Prefetch-файла
  /// @return Номер версии формата: 17 (Windows XP), 23 (Vista), 26 (Windows 8+)
  [[nodiscard]] virtual uint8_t getFormatVersion() const noexcept = 0;

  /// @brief Проверяет поддержку версии
  /// @param[in] version Версия для проверки
  /// @return true если версия поддерживается парсером
  [[nodiscard]] virtual bool isVersionSupported(
      PrefetchFormatVersion version) const noexcept = 0;

  /// @}
};

}
