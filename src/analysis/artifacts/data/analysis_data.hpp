/// @file analysis_data.hpp
/// @brief Информация о запускавшемся ПО

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "parsers/prefetch/metadata/file_metric.hpp"
#include "parsers/prefetch/metadata/volume_info.hpp"

namespace WindowsDiskAnalysis {

/// @struct AmcacheEntry
/// @brief Информация о записи из Amcache
struct AmcacheEntry {
  // Основная информация
  std::string file_path;  ///< Путь к исполняемому файлу
  std::string name;       ///< Название файла
  std::string file_hash;  ///< SHA-1 хэш файла
  std::string version;    ///< Версия ПО
  std::string source = "Amcache";  ///< Источник записи (Amcache/Amcache(BCF))

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

/// @struct AutorunEntry
/// @brief Информация о записи автозапуска
struct AutorunEntry {
  std::string name;      ///< Название записи автозапуска
  std::string path;      ///< Полный путь к исполняемому файлу
  std::string command;   ///< Командная строка запуска
  std::string location;  ///< Место расположения в реестре или файловой системе
};

/// @struct ProcessInfo
/// @brief Информация о процессе
struct ProcessInfo {
  std::string filename;                ///< Имя файла
  std::vector<std::string> run_times;  ///< Временные метки запусков процесса
  uint32_t run_count = 0;              ///< Количество запусков процесса
  std::string command;                 ///< Командная строка запуска
  std::vector<std::string> users;  ///< Пользователи, от имени которых запускалось ПО
  std::vector<std::string> user_sids;  ///< SID пользователей
  std::vector<std::string> logon_ids;  ///< Идентификаторы сеансов входа (LogonId)
  std::vector<std::string> logon_types;  ///< Типы входа (LogonType)
  std::string elevation_type;  ///< Тип повышения привилегий (TokenElevationType)
  std::string elevated_token;  ///< Признак повышенного токена
  std::string integrity_level;  ///< Уровень целостности процесса/токена
  std::vector<std::string>
      privileges;  ///< Список привилегий безопасности (например SeDebugPrivilege)
  std::vector<PrefetchAnalysis::VolumeInfo>
      volumes;  ///< Тома, на которых обнаружена активность процесса
  std::vector<PrefetchAnalysis::FileMetric>
      metrics;  ///< Файлы, к которым процесс обращался по данным Prefetch
  std::vector<std::string>
      evidence_sources;  ///< Источники доказательств (Prefetch, EventLog и др.)
  std::vector<std::string>
      tamper_flags;  ///< Флаги подозрительной модификации артефактов
  std::string first_seen_utc;  ///< Минимальная временная метка корреляции
  std::string last_seen_utc;   ///< Максимальная временная метка корреляции
  std::vector<std::string>
      timeline_artifacts;  ///< Таймлайн артефактов с деталями источника
  std::vector<std::string>
      recovered_from;  ///< Источники восстановления (USN, $LogFile, VSS и др.)
};

/// @struct RecoveryEvidence
/// @brief Базовая запись доказательства восстановления (USN/VSS и др.)
struct RecoveryEvidence {
  std::string executable_path;  ///< Путь к исполняемому файлу
  std::string source;           ///< Источник (например "USN" или "VSS")
  std::string recovered_from;   ///< Категория восстановления (USN/$LogFile/...)
  std::string timestamp;        ///< Временная метка восстановления (если есть)
  std::string details;          ///< Технические детали для последующей корреляции
  std::string tamper_flag;      ///< Дополнительный флаг подозрительности
};

/// @struct NetworkConnection
/// @brief Информация о сетевом подключении
struct NetworkConnection {
  uint32_t event_id = 0;        ///< ID события журнала (например 5156/5157)
  std::string timestamp;        ///< Время сетевого события
  std::string process_name;     ///< Имя процесса, установившего соединение
  uint32_t process_id = 0;      ///< PID процесса
  std::string application;      ///< Полный путь к приложению (если известен)
  std::string source_ip;        ///< Исходный IP-адрес
  uint16_t source_port = 0;     ///< Исходный порт
  std::string dest_ip;          ///< Целевой IP-адрес
  uint16_t dest_port = 0;       ///< Целевой порт
  std::string protocol;         ///< Протокол (TCP/UDP/ICMP/...)
  std::string direction;        ///< Направление (inbound/outbound)
  std::string action;           ///< Действие (allow/block)
};

}  // namespace WindowsDiskAnalysis
