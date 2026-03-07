#include "amcache_analyzer.hpp"

#include <algorithm>
#include <filesystem>
#include <string_view>
#include <unordered_set>

#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "common/utils.hpp"

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;
namespace {

constexpr std::string_view kVersionDefaultsSection = "VersionDefaults";

std::string getConfigValueWithFallback(const Config& config,
                                       const std::string& version,
                                       const std::string& key) {
  if (config.hasKey(version, key)) {
    return config.getString(version, key, "");
  }

  if (config.hasKey(std::string(kVersionDefaultsSection), key)) {
    return config.getString(std::string(kVersionDefaultsSection), key, "");
  }

  return {};
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

  amcache_path_ = getConfigValueWithFallback(config, os_version_, "AmcachePath");
  trim(amcache_path_);
  std::ranges::replace(amcache_path_, '\\', '/');

  std::string keys_str =
      getConfigValueWithFallback(config, os_version_, "AmcacheKeys");
  auto keys = split(keys_str, ',');
  for (auto& key : keys) {
    trim(key);
    if (!key.empty()) {
      amcache_keys_.push_back(key);
    }
  }

  logger->debug("Конфигурация Amcache для {}: путь={}, ключи={}", os_version_,
                amcache_path_, keys_str);

  // Загружаем расширенные параметры из [VersionDefaults]
  constexpr auto kDefaults = std::string_view("VersionDefaults");
  try {
    config_.enable_inventory_application = config.getBool(
        std::string(kDefaults), "EnableInventoryApplication",
        config_.enable_inventory_application);
  } catch (...) {}
  try {
    config_.enable_inventory_shortcut = config.getBool(
        std::string(kDefaults), "EnableInventoryShortcut",
        config_.enable_inventory_shortcut);
  } catch (...) {}
  {
    const std::string app_key =
        getConfigValueWithFallback(config, os_version_, "AmcacheInventoryApplicationKey");
    if (!app_key.empty()) {
      config_.inventory_application_key = app_key;
    }
  }
  {
    const std::string sc_key =
        getConfigValueWithFallback(config, os_version_, "AmcacheInventoryShortcutKey");
    if (!sc_key.empty()) {
      config_.inventory_shortcut_key = sc_key;
    }
  }
}

std::vector<AmcacheEntry> AmcacheAnalyzer::collect(
    const std::string& disk_root) const {
  std::vector<AmcacheEntry> results;
  auto logger = GlobalLogger::get();

  if (amcache_path_.empty() || amcache_keys_.empty()) {
    logger->warn("Анализ Amcache пропущен: не настроен путь или ключи");
    return results;
  }

  const std::string full_path = disk_root + amcache_path_;

  if (!fs::exists(full_path)) {
    logger->warn("Файл Amcache не найден");
    logger->debug("Проверенный путь Amcache: {}", full_path);
    return results;
  }

  try {
    logger->debug("Анализ куста Amcache: {}", full_path);

    for (const auto& key : amcache_keys_) {
      try {
        auto subkeys = parser_->listSubkeys(full_path, key);
        logger->debug("Найдено {} подразделов в {}", subkeys.size(), key);

        for (const auto& subkey : subkeys) {
          try {
            std::string full_subkey_path = key + "/" + subkey;
            logger->debug("Обработка подраздела: {}", full_subkey_path);

            auto values = parser_->getKeyValues(full_path, full_subkey_path);

            if (key.find("InventoryApplication") != std::string::npos) {
              results.push_back(processInventoryApplicationEntry(values));
            }
          } catch (const std::exception& e) {
            logger->warn("Пропущен подраздел Amcache");
            logger->debug("Ошибка обработки подраздела \"{}\": {}", subkey,
                          e.what());
          }
        }
      } catch (const std::exception& e) {
        logger->error("Ошибка доступа к ключу Amcache");
        logger->debug("Ошибка доступа к ключу \"{}\": {}", key, e.what());
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
          results.push_back(std::move(entry));
        }
      }
    }

    logger->info("Извлечено {} записей из Amcache", results.size());
  } catch (const std::exception& e) {
    logger->error("Критическая ошибка анализа Amcache");
    logger->debug("Критическая ошибка анализа Amcache: {}", e.what());
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
        if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
          return value->getAsQword();
        }
        if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD) {
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
        if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
            value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
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
      logger->debug("Ошибка обработки значения Amcache \"{}\": {}", name,
                    e.what());
    }
  }

  // Конвертируем временные метки в читаемый формат
  if (entry.modification_time > 0) {
    try {
      entry.modification_time_str = filetimeToString(entry.modification_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени изменения Amcache");
      logger->debug("Ошибка конвертации modification_time: {}", e.what());
    }
  }

  if (entry.install_time > 0) {
    try {
      entry.install_time_str = filetimeToString(entry.install_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени установки Amcache");
      logger->debug("Ошибка конвертации install_time: {}", e.what());
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
        } catch (...) {}
      }

      // RootDirPath используется как file_path (прямого пути к exe нет)
      if (!entry.alternate_path.empty()) {
        entry.file_path = entry.alternate_path;
      } else if (!entry.name.empty()) {
        entry.file_path = entry.name;
      }

      if (!entry.file_path.empty() && !entry.name.empty()) {
        results.push_back(std::move(entry));
      }
    }
  } catch (const std::exception& e) {
    logger->debug("InventoryApplication пропущен: {}", e.what());
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
        } catch (...) {}
      }

      if (!entry.file_path.empty()) {
        if (entry.name.empty()) entry.name = entry.file_path;
        results.push_back(std::move(entry));
      }
    }
  } catch (const std::exception& e) {
    logger->debug("InventoryApplicationShortcut пропущен: {}", e.what());
  }
  return results;
}
