/// @file data.hpp
/// @brief Реализация работы с данными Prefetch-файлов Windows

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "parsers/prefetch/metadata/file_metric.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"
#include "data_storage.hpp"
#include "idata.hpp"

namespace PrefetchAnalysis {

/// @class PrefetchData
/// @brief Конкретная реализация интерфейса IPrefetchData
/// @details Обеспечивает доступ к метаданным Prefetch-файлов всех
/// поддерживаемых версий Windows (XP-Win11). Хранит данные в перемещаемом
/// контейнере для эффективной работы с памятью
class PrefetchData : public IPrefetchData {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор перемещения
  /// @param[in] storage Контейнер с данными Prefetch-файла
  /// @post Все данные ownership передаются текущему объекту
  explicit PrefetchData(PrefetchDataStorage&& storage);

  /// @}

  /// @name Геттеры
  /// @{

  /// @copydoc IPrefetchData::getExecutableName
  [[nodiscard]] std::string getExecutableName() const noexcept override;

  /// @copydoc IPrefetchData::getPrefetchHash
  [[nodiscard]] uint32_t getPrefetchHash() const noexcept override;

  /// @copydoc IPrefetchData::getRunCount
  [[nodiscard]] uint32_t getRunCount() const noexcept override;

  /// @copydoc IPrefetchData::getRunTimes
  [[nodiscard]] const std::vector<uint64_t>& getRunTimes()
      const noexcept override;

  /// @copydoc IPrefetchData::getLastRunTime
  [[nodiscard]] uint64_t getLastRunTime() const noexcept override;

  /// @copydoc IPrefetchData::getVolumes
  [[nodiscard]] const std::vector<VolumeInfo>& getVolumes()
      const noexcept override;

  /// @copydoc IPrefetchData::getMainVolume
  [[nodiscard]] VolumeInfo getMainVolume() const override;

  /// @copydoc IPrefetchData::getMetrics
  [[nodiscard]] const std::vector<FileMetric>& getMetrics()
      const noexcept override;

  /// @copydoc IPrefetchData::getDllMetrics
  /// @details Реализация фильтрует метрики по расширению .dll
  [[nodiscard]] std::vector<FileMetric> getDllMetrics() const override;

  /// @copydoc IPrefetchData::getFormatVersion
  [[nodiscard]] uint8_t getFormatVersion() const noexcept override;

  /// @}

  /// @name Доступ к метаданным
  /// @{

  /// @copydoc IPrefetchData::isVersionSupported
  [[nodiscard]] bool isVersionSupported(
      PrefetchFormatVersion version) const noexcept override;

  /// @}

 private:
  PrefetchDataStorage storage_;  ///< Внутреннее хранилище данных. Содержит
                                 ///< сырые распарсенные данные
};

}
