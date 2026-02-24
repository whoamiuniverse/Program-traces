#include "amcache_analyzer.hpp"

#include <algorithm>
#include <filesystem>

#include "../../../../utils/config/config.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../../../utils/utils.hpp"

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;

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

  amcache_path_ = config.getString(os_version_, "AmcachePath", "");
  trim(amcache_path_);
  std::ranges::replace(amcache_path_, '\\', '/');

  std::string keys_str = config.getString(os_version_, "AmcacheKeys", "");
  auto keys = split(keys_str, ',');
  for (auto& key : keys) {
    trim(key);
    if (!key.empty()) {
      amcache_keys_.push_back(key);
    }
  }

  logger->debug("Конфигурация Amcache для {}: путь={}, ключи={}", os_version_,
                amcache_path_, keys_str);
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
    logger->warn("Файл Amcache не найден: {}", full_path);
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
            logger->warn("Ошибка обработки подраздела {}: {}", subkey,
                         e.what());
          }
        }
      } catch (const std::exception& e) {
        logger->error("Ошибка доступа к ключу {}: {}", key, e.what());
      }
    }

    logger->info("Извлечено {} записей из Amcache", results.size());
  } catch (const std::exception& e) {
    logger->error("Критическая ошибка анализа Amcache: {}", e.what());
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
      }
    } catch (const std::exception& e) {
      logger->warn("Ошибка обработки значения '{}': {}", name, e.what());
    }
  }

  // Конвертируем временные метки в читаемый формат
  if (entry.modification_time > 0) {
    try {
      entry.modification_time_str = filetimeToString(entry.modification_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени изменения: {}", e.what());
    }
  }

  if (entry.install_time > 0) {
    try {
      entry.install_time_str = filetimeToString(entry.install_time);
    } catch (const std::exception& e) {
      logger->warn("Ошибка конвертации времени установки: {}", e.what());
    }
  }

  return entry;
}
