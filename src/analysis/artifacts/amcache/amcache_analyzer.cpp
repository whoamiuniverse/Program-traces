#include "amcache_analyzer.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <unordered_set>

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/config_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;
namespace {

std::string stripUtf8Bom(std::string line) {
  constexpr char kUtf8Bom[] = "\xEF\xBB\xBF";
  if (line.size() >= 3 && line.compare(0, 3, kUtf8Bom) == 0) {
    line.erase(0, 3);
  }
  return line;
}

}  // namespace

AmcacheAnalyzer::AmcacheAnalyzer(
    std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
    std::string os_version, std::string ini_path)
    : parser_(std::move(parser)),
      os_version_(std::move(os_version)),
      ini_path_(std::move(ini_path)) {
  trim(os_version_);
  loadConfiguration();
}

void AmcacheAnalyzer::loadConfiguration() {
  Config config(ini_path_, false, false);
  auto logger = GlobalLogger::get();

  amcache_path_ =
      ConfigUtils::getWithVersionFallback(config, os_version_, "AmcachePath");
  trim(amcache_path_);
  std::ranges::replace(amcache_path_, '\\', '/');

  recent_file_cache_path_ = ConfigUtils::getWithVersionFallback(
      config, os_version_, "RecentFileCachePath");
  trim(recent_file_cache_path_);
  std::ranges::replace(recent_file_cache_path_, '\\', '/');

  std::string keys_str =
      ConfigUtils::getWithVersionFallback(config, os_version_, "AmcacheKeys");
  auto keys = split(keys_str, ',');
  for (auto& key : keys) {
    trim(key);
    if (!key.empty()) {
      amcache_keys_.push_back(key);
    }
  }

  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug,
              "Конфигурация Amcache для {}: путь={}, ключи={}", os_version_,
              amcache_path_, keys_str);

  // Загружаем расширенные параметры из [VersionDefaults]
  constexpr auto kDefaults = std::string_view("VersionDefaults");
  try {
    config_.enable_inventory_application =
        config.getBool(std::string(kDefaults), "EnableInventoryApplication",
                       config_.enable_inventory_application);
  } catch (...) {
  }
  try {
    config_.enable_inventory_shortcut =
        config.getBool(std::string(kDefaults), "EnableInventoryShortcut",
                       config_.enable_inventory_shortcut);
  } catch (...) {
  }
  try {
    config_.enable_inventory_driver = config.getBool(
        std::string(kDefaults), "EnableInventoryApplicationDriver",
        config_.enable_inventory_driver);
  } catch (...) {
  }
  {
    const std::string app_key = ConfigUtils::getWithVersionFallback(
        config, os_version_, "AmcacheInventoryApplicationKey");
    if (!app_key.empty()) {
      config_.inventory_application_key = app_key;
    }
  }
  {
    const std::string sc_key = ConfigUtils::getWithVersionFallback(
        config, os_version_, "AmcacheInventoryShortcutKey");
    if (!sc_key.empty()) {
      config_.inventory_shortcut_key = sc_key;
    }
  }
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collect(
    const std::string& disk_root) const {
  std::vector<AmcacheEntry> results;
  auto logger = GlobalLogger::get();

  if (amcache_path_.empty() && recent_file_cache_path_.empty()) {
    logger->warn("Анализ Amcache пропущен: не настроен путь к hive или BCF");
    return results;
  }

  std::optional<fs::path> resolved_hive_path;
  if (!amcache_path_.empty()) {
    const fs::path hive_candidate = fs::path(disk_root) / amcache_path_;
    resolved_hive_path =
        ExecutionEvidenceDetail::findPathCaseInsensitive(hive_candidate);
  }

  if (resolved_hive_path.has_value() && !amcache_keys_.empty()) {
    const std::string full_path = resolved_hive_path->string();

    try {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug, "Анализ куста Amcache: {}", full_path);

      for (const auto& key : amcache_keys_) {
        try {
          auto subkeys = parser_->listSubkeys(full_path, key);
          logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                      spdlog::level::debug, "Найдено {} подразделов в {}",
                      subkeys.size(), key);

          for (const auto& subkey : subkeys) {
            try {
              std::string full_subkey_path = key + "/" + subkey;
              logger->log(
                  spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug, "Обработка подраздела: {}",
                  full_subkey_path);

              auto values = parser_->getKeyValues(full_path, full_subkey_path);

              if (key.find("InventoryApplication") != std::string::npos) {
                auto entry = processInventoryApplicationEntry(values);
                entry.source = "Amcache";
                results.push_back(std::move(entry));
              }
            } catch (const std::exception& e) {
              logger->warn("Пропущен подраздел Amcache");
              logger->log(
                  spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "Ошибка обработки подраздела \"{}\": {}", subkey, e.what());
            }
          }
        } catch (const std::exception& e) {
          logger->error("Ошибка доступа к ключу Amcache");
          logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                      spdlog::level::debug, "Ошибка доступа к ключу \"{}\": {}",
                      key, e.what());
        }
      }

      // Собираем ключи file_path из InventoryApplicationFile для дедупликации
      std::unordered_set<std::string> seen_paths;
      seen_paths.reserve(results.size());
      for (const auto& entry : results) {
        if (!entry.file_path.empty()) {
          seen_paths.insert(to_lower(entry.file_path));
        }
      }

      // Добавляем записи из Root/InventoryApplication
      if (config_.enable_inventory_application) {
        auto app_entries = collectInventoryApplication(full_path);
        for (auto& entry : app_entries) {
          const std::string key = to_lower(entry.file_path);
          if (seen_paths.insert(key).second) {
            entry.source = "Amcache";
            results.push_back(std::move(entry));
          }
        }
      }

      // Добавляем записи из Root/InventoryApplicationShortcut
      if (config_.enable_inventory_shortcut) {
        auto sc_entries = collectInventoryShortcut(full_path);
        for (auto& entry : sc_entries) {
          const std::string key = to_lower(entry.file_path);
          if (seen_paths.insert(key).second) {
            entry.source = "Amcache";
            results.push_back(std::move(entry));
          }
        }
      }

      // Добавляем записи из Root/InventoryApplicationDriver (Windows 11 24H2+)
      if (config_.enable_inventory_driver) {
        auto drv_entries = collectInventoryApplicationDriver(full_path);
        for (auto& entry : drv_entries) {
          const std::string key = to_lower(entry.file_path);
          if (seen_paths.insert(key).second) {
            entry.source = "Amcache(Driver)";
            results.push_back(std::move(entry));
          }
        }
      }

      logger->info("Извлечено {} записей из Amcache", results.size());
      return results;
    } catch (const std::exception& e) {
      logger->error("Критическая ошибка анализа Amcache");
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "Критическая ошибка анализа Amcache: {}", e.what());
    }
  }

  if (!recent_file_cache_path_.empty()) {
    const fs::path bcf_candidate =
        fs::path(disk_root) / recent_file_cache_path_;
    if (const auto resolved_bcf =
            ExecutionEvidenceDetail::findPathCaseInsensitive(bcf_candidate);
        resolved_bcf.has_value()) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug, "Анализ RecentFileCache.bcf: {}",
                  resolved_bcf->string());
      return collectFromRecentFileCache(resolved_bcf->string());
    }
  }

  if (!amcache_path_.empty()) {
    logger->warn("Файл Amcache не найден");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug, "Проверенный путь Amcache: {}",
                amcache_path_);
  }

  logger->warn("Файл RecentFileCache.bcf не найден");
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug, "Проверенный путь RecentFileCache.bcf: {}",
              recent_file_cache_path_);

  return results;
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collectFromRecentFileCache(
    const std::string& path) const {
  std::vector<AmcacheEntry> results;
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return results;
  }

  std::string line;
  while (std::getline(file, line)) {
    line = stripUtf8Bom(std::move(line));
    trim(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }

    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
    std::ranges::replace(line, '\\', '/');

    AmcacheEntry entry;
    entry.source = "Amcache(BCF)";
    entry.file_path = line;
    entry.name = fs::path(line).filename().string();
    if (!entry.file_path.empty()) {
      results.push_back(std::move(entry));
    }
  }

  return results;
}

AmcacheEntry AmcacheAnalyzer::processInventoryApplicationEntry(
    const std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>&
        values) {
  AmcacheEntry entry;
  auto logger = GlobalLogger::get();

  // Обрабатываем каждое значение в векторе
  for (const auto& value : values) {
    const std::string& full_name = value->getName();

    // Извлекаем последнюю часть имени после последнего '/'
    size_t last_slash = full_name.find_last_of('/');
    std::string name = (last_slash != std::string::npos)
                           ? full_name.substr(last_slash + 1)
                           : full_name;

    try {
      auto parseUInt64Value = [&]() -> uint64_t {
        if (value->getType() ==
            RegistryAnalysis::RegistryValueType::REG_QWORD) {
          return value->getAsQword();
        }
        if (value->getType() ==
            RegistryAnalysis::RegistryValueType::REG_DWORD) {
          return value->getAsDword();
        }
        std::string raw = value->getDataAsString();
        trim(raw);
        if (raw.empty()) return 0;
        return std::stoull(raw);
      };

      if (name == "LowerCaseLongPath") {
        entry.file_path = value->getDataAsString();
        entry.name = getLastPathComponent(entry.file_path, '/');
      } else if (name == "Name") {
        entry.name = value->getDataAsString();
      } else if (name == "FileId") {
        entry.file_hash = value->getDataAsString();
      } else if (name == "Version") {
        entry.version = value->getDataAsString();
      } else if (name == "Publisher") {
        entry.publisher = value->getDataAsString();
      } else if (name == "Description") {
        entry.description = value->getDataAsString();
      } else if (name == "Size") {
        if (value->getType() ==
            RegistryAnalysis::RegistryValueType::REG_QWORD) {
          entry.file_size = value->getAsQword();
        } else if (value->getType() ==
                   RegistryAnalysis::RegistryValueType::REG_DWORD) {
          entry.file_size = value->getAsDword();
        }
      } else if (name == "AlternatePath") {
        entry.alternate_path = value->getDataAsString();
      } else if (name == "Mtime" || name == "LastWriteTime" ||
                 name == "LastModifiedTime") {
        entry.modification_time = parseUInt64Value();
      } else if (name == "InstallDate" || name == "InstallTime" ||
                 name == "InstallDateArpLastModified") {
        entry.install_time = parseUInt64Value();
      } else if (name == "IsDeleted" || name == "Deleted") {
        if (value->getType() ==
                RegistryAnalysis::RegistryValueType::REG_DWORD ||
            value->getType() ==
                RegistryAnalysis::RegistryValueType::REG_QWORD) {
          entry.is_deleted = parseUInt64Value() != 0;
        } else {
          std::string deleted = to_lower(value->getDataAsString());
          trim(deleted);
          entry.is_deleted =
              (deleted == "1" || deleted == "true" || deleted == "yes");
        }
      }
    } catch (const std::exception& e) {
      logger->warn("Пропущено значение Amcache");
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "Ошибка обработки значения Amcache \"{}\": {}", name,
                  e.what());
    }
  }

  // Конвертируем временные метки в читаемый формат
  if (entry.modification_time > 0) {
    try {
      entry.modification_time_str = filetimeToString(entry.modification_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени изменения Amcache");
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "Ошибка конвертации modification_time: {}", e.what());
    }
  }

  if (entry.install_time > 0) {
    try {
      entry.install_time_str = filetimeToString(entry.install_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени установки Amcache");
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug, "Ошибка конвертации install_time: {}",
                  e.what());
    }
  }

  return entry;
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collectInventoryApplication(
    const std::string& hive_path) const {
  std::vector<AmcacheEntry> results;
  const auto logger = GlobalLogger::get();
  try {
    std::vector<std::string> app_subkeys =
        parser_->listSubkeys(hive_path, config_.inventory_application_key);

    for (const auto& subkey : app_subkeys) {
      const std::string app_key =
          config_.inventory_application_key + "/" + subkey;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(hive_path, app_key);
      } catch (...) {
        continue;
      }

      AmcacheEntry entry;
      entry.name = subkey;  // ProgramId как запасное имя

      for (const auto& value : values) {
        const std::string val_name_lower =
            to_lower(getLastPathComponent(value->getName(), '/'));
        try {
          if (val_name_lower == "name") {
            const std::string name = trim_copy(value->getDataAsString());
            if (!name.empty()) entry.name = name;
          } else if (val_name_lower == "publisher") {
            entry.publisher = trim_copy(value->getDataAsString());
          } else if (val_name_lower == "version") {
            entry.version = trim_copy(value->getDataAsString());
          } else if (val_name_lower == "rootdirpath") {
            entry.alternate_path = trim_copy(value->getDataAsString());
          } else if (val_name_lower == "installdate") {
            entry.install_time_str = trim_copy(value->getDataAsString());
          }
        } catch (...) {
        }
      }

      // InventoryApplication может содержать директорию установки,
      // а не путь к executable. В process CSV включаем только записи
      // с валидным путем к исполняемому файлу.
      if (!entry.alternate_path.empty() &&
          PathUtils::isExecutionPathCandidate(entry.alternate_path)) {
        entry.file_path = entry.alternate_path;
      } else if (PathUtils::isExecutionPathCandidate(entry.name)) {
        entry.file_path = entry.name;
      } else {
        entry.file_path.clear();
      }

      if (!entry.file_path.empty()) {
        results.push_back(std::move(entry));
      }
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug, "InventoryApplication пропущен: {}",
                e.what());
  }
  return results;
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collectInventoryApplicationDriver(
    const std::string& hive_path) const {
  std::vector<AmcacheEntry> results;
  const auto logger = GlobalLogger::get();
  try {
    const std::vector<std::string> driver_subkeys =
        parser_->listSubkeys(hive_path, config_.inventory_driver_key);

    for (const auto& subkey : driver_subkeys) {
      const std::string driver_key =
          config_.inventory_driver_key + "/" + subkey;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(hive_path, driver_key);
      } catch (...) {
        continue;
      }

      AmcacheEntry entry;
      entry.name = subkey;  // DriverId как запасное имя

      for (const auto& value : values) {
        const std::string val_name =
            to_lower(getLastPathComponent(value->getName(), '/'));
        try {
          if (val_name == "drivername") {
            const std::string name = trim_copy(value->getDataAsString());
            if (!name.empty()) entry.name = name;
          } else if (val_name == "driverversion") {
            entry.version = trim_copy(value->getDataAsString());
          } else if (val_name == "driverinfpath") {
            // .inf путь — сохраняем как file_path (следствие загрузки драйвера)
            entry.file_path = trim_copy(value->getDataAsString());
          } else if (val_name == "driverid") {
            entry.file_hash = trim_copy(value->getDataAsString());
          } else if (val_name == "driverdate" || val_name == "installdate") {
            entry.modification_time_str = trim_copy(value->getDataAsString());
          }
        } catch (...) {
        }
      }

      // Нормализуем разделители пути
      std::ranges::replace(entry.file_path, '\\', '/');

      if (!entry.file_path.empty()) {
        results.push_back(std::move(entry));
      }
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug, "InventoryApplicationDriver пропущен: {}",
                e.what());
  }
  return results;
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collectInventoryShortcut(
    const std::string& hive_path) const {
  std::vector<AmcacheEntry> results;
  const auto logger = GlobalLogger::get();
  try {
    std::vector<std::string> shortcut_subkeys =
        parser_->listSubkeys(hive_path, config_.inventory_shortcut_key);

    for (const auto& subkey : shortcut_subkeys) {
      const std::string shortcut_key =
          config_.inventory_shortcut_key + "/" + subkey;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(hive_path, shortcut_key);
      } catch (...) {
        continue;
      }

      AmcacheEntry entry;
      for (const auto& value : values) {
        const std::string val_name_lower =
            to_lower(getLastPathComponent(value->getName(), '/'));
        try {
          if (val_name_lower == "shortcutname") {
            entry.name = trim_copy(value->getDataAsString());
          } else if (val_name_lower == "target") {
            entry.file_path = trim_copy(value->getDataAsString());
          }
        } catch (...) {
        }
      }

      if (!entry.file_path.empty()) {
        if (entry.name.empty()) entry.name = entry.file_path;
        results.push_back(std::move(entry));
      }
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "InventoryApplicationShortcut пропущен: {}", e.what());
  }
  return results;
}
