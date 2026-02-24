/// @file analysis_data.hpp
/// @brief Информация о запускавшемся ПО

#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "../../../../parsers/prefetch/metadata/file_metric.hpp"
#include "../../../../parsers/prefetch/metadata/volume_info.hpp"

namespace WindowsDiskAnalysis {

/// @brief Информация о записи из Amcache
struct AmcacheEntry {
  // Основная информация
  std::string file_path;  ///< Путь к исполняемому файлу
  std::string name;       ///< Название файла
  std::string file_hash;  ///< SHA-1 хэш файла
  std::string version;    ///< Версия ПО

  // Временные метки
  uint64_t modification_time = 0;     ///< Время последнего изменения (FILETIME)
  std::string modification_time_str;  ///< Форматированное время изменения
  uint64_t install_time = 0;          ///< Время установки (для приложений)
  std::string install_time_str;       ///< Форматированное время установки

  // Дополнительные атрибуты
  std::string publisher;       ///< Издатель программы
  std::string description;     ///< Описание файла
  uint64_t file_size = 0;      ///< Размер файла в байтах
  std::string alternate_path;  ///< Альтернативный путь к файлу
  bool is_deleted = false;     ///< Флаг удаленного файла
};

/// @brief Информация о записи автозапуска
struct AutorunEntry {
  std::string name;      ///< Название записи автозапуска
  std::string path;      ///< Полный путь к исполняемому файлу
  std::string command;   ///< Командная строка запуска
  std::string location;  ///< Место расположения в реестре или файловой системе
};

/// @brief Информация о процессе
struct ProcessInfo {
  std::string filename;                ///< Имя файла
  std::vector<std::string> run_times;  ///< Временные метки запусков процесса
  uint32_t run_count = 0;              ///< Количество запусков процесса
  std::string command;                 ///< Командная строка запуска
  std::vector<PrefetchAnalysis::VolumeInfo> volumes;
  std::vector<PrefetchAnalysis::FileMetric> metrics;
};

/// @brief Информация о сетевом подключении
struct NetworkConnection {
  std::string process_name;    ///< Имя процесса, установившего соединение
  std::string local_address;   ///< Локальный IP-адрес
  std::string remote_address;  ///< Удалённый IP-адрес
  uint16_t port = 0;           ///< Номер порта
  std::string protocol;        ///< Протокол соединения (TCP/UDP)
};

}
