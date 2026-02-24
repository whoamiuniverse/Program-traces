/// @file data_storage.hpp
/// @brief Структура хранения данных Prefetch-файла

#pragma once

#include <cstdint>
#include <vector>

#include "parsers/prefetch/metadata/file_metric.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"

namespace PrefetchAnalysis {

/// @struct PrefetchDataStorage
/// @brief Plain Old Data (POD) структура для хранения сырых данных
/// Prefetch-файла
struct PrefetchDataStorage {
  std::string executable_name;  ///< Исполняемое имя Prefetch-файла в формате
                                ///< "NAME.EXE-XXXXXXXX.pf"
  uint32_t prefetch_hash = 0;   ///< 32-битный хеш пути к исполняемому файлу
  uint32_t run_count = 0;  ///< Число запусков приложения (может быть неточным)
  std::vector<uint64_t>
      run_times;  ///< Временные метки запусков в формате FILETIME
  std::vector<VolumeInfo>
      volumes;  ///< Информация о томах, используемых приложением
  std::vector<FileMetric> metrics;  ///< Метрики доступа к файлам приложения
  uint8_t format_version =
      0;  ///< Версия формата Prefetch: 17(XP),23(Vista),26(Win8+)
  uint64_t last_run_time = 0;  ///< Время последнего запуска в формате FILETIME
};

}
