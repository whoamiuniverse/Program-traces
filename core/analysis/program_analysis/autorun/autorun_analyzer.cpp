#include "autorun_analyzer.hpp"

#include <utility>

#include "../../../../utils/config/config.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../../../utils/utils.hpp"

namespace WindowsDiskAnalysis {

AutorunAnalyzer::AutorunAnalyzer(
    std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
    std::string os_version, const std::string& ini_path)
    : parser_(std::move(parser)), os_version_(std::move(os_version)) {
  trim(os_version_);
  loadConfigurations(ini_path);
}

void AutorunAnalyzer::loadConfigurations(const std::string& ini_path) {
  Config config(ini_path, false, false);
  const auto logger = GlobalLogger::get();

  // Получаем список версий
  std::string versions_str = config.getString("General", "Versions", "");

  // Обрабатываем каждую версию
  for (auto versions = split(versions_str, ','); auto& version : versions) {
    trim(version);
    if (version.empty()) continue;

    AutorunConfig cfg;

    // Загрузка пути к кусту реестра
    std::string reg_path = config.getString(version, "RegistryPath", "");
    trim(reg_path);
    if (!reg_path.empty()) {
      std::ranges::replace(reg_path, '\\', '/');
      cfg.registry_path = reg_path;
    }

    // Загрузка ключей реестра
    std::string reg_keys = config.getString(version, "RegistryKeys", "");
    auto reg_key_list = split(reg_keys, ',');
    for (auto& key : reg_key_list) {
      trim(key);
      if (key.empty()) continue;
      std::ranges::replace(key, '\\', '/');
      cfg.registry_locations.push_back(key);
    }

    // Загрузка путей файловой системы
    std::string fs_paths = config.getString(version, "FilesystemPaths", "");
    auto fs_path_list = split(fs_paths, ',');
    for (auto& path : fs_path_list) {
      trim(path);
      if (!path.empty()) {
        cfg.filesystem_paths.push_back(path);
      }
    }

    // Сохраняем конфигурацию
    configs_[version] = cfg;

    // Логируем результат
    logger->debug(
        "Загружена конфигурация для \"{}\": куст реестра \"{}\", {} ключей, {} "
        "путей ФС",
        version, cfg.registry_path.empty() ? "по умолчанию" : cfg.registry_path,
        cfg.registry_locations.size(), cfg.filesystem_paths.size());
  }
}

std::vector<AutorunEntry> AutorunAnalyzer::collect(
    const std::string& disk_root) {
  std::vector<AutorunEntry> results;
  const auto logger = GlobalLogger::get();

  // Проверяем наличие конфигурации для версии ОС
  if (!configs_.contains(os_version_)) {
    logger->warn("Отсутствует конфигурация автозапуска для версии ОС: {}",
                 os_version_);
    return results;
  }

  // Анализ реестра
  auto registry_entries = analyzeRegistry(disk_root);
  results.insert(results.end(),
                 std::make_move_iterator(registry_entries.begin()),
                 std::make_move_iterator(registry_entries.end()));

  // Анализ файловой системы
  auto fs_entries = analyzeFilesystem(disk_root);
  results.insert(results.end(), std::make_move_iterator(fs_entries.begin()),
                 std::make_move_iterator(fs_entries.end()));

  logger->info("Найдено \"{}\" записей автозапуска", results.size());
  return results;
}

std::vector<AutorunEntry> AutorunAnalyzer::analyzeRegistry(
    const std::string& disk_root) {
  std::vector<AutorunEntry> entries;
  const auto& cfg = configs_[os_version_];
  const auto logger = GlobalLogger::get();

  // Проверка доступности пути к кусту реестра
  if (cfg.registry_path.empty()) {
    logger->warn("Для версии \"{}\" не указан путь к кусту реестра",
                 os_version_);
    return entries;
  }

  const std::string full_reg_path = disk_root + cfg.registry_path;
  if (!std::filesystem::exists(full_reg_path)) {
    logger->warn("Файл куста реестра не найден: \"{}\"", full_reg_path);
    return entries;
  }

  // Обработка всех ключей реестра
  for (const auto& location : cfg.registry_locations) {
    try {
      auto values = parser_->getKeyValues(full_reg_path, location);
      for (const auto& value : values) {
        AutorunEntry entry;
        entry.name = value->getName();
        trim(entry.name);

        entry.command = value->getDataAsString();
        trim(entry.command);

        entry.location = "Реестр: " + location;

        // Извлечение пути из командной строки
        if (!entry.command.empty()) {
          const size_t start = entry.command.find_first_not_of(" \t\"");
          if (start != std::string::npos) {
            const size_t end = entry.command.find_last_not_of(" \t\"");
            entry.path = entry.command.substr(start, end - start + 1);
          }
        }

        if (!entry.path.empty()) {
          entries.push_back(std::move(entry));
        }
      }
    } catch (const std::exception& e) {
      logger->warn("Пропущен ключ реестра \"{}\": \"{}\"", location, e.what());
    }
  }

  return entries;
}

std::vector<AutorunEntry> AutorunAnalyzer::analyzeFilesystem(
    const std::string& disk_root) {
  std::vector<AutorunEntry> entries;
  const auto& cfg = configs_[os_version_];
  const auto logger = GlobalLogger::get();

  for (const auto& path : cfg.filesystem_paths) {
    try {
      if (path.find('*') != std::string::npos) {
        processWildcardPath(disk_root, path, entries);
      } else {
        std::string full_path = disk_root + path;
        trim(full_path);

        if (std::filesystem::exists(full_path)) {
          entries.push_back(createFilesystemEntry(full_path, path));
        }
      }
    } catch (const std::exception& e) {
      logger->warn("Пропущен путь ФС \"{}\": \"{}\"", path, e.what());
    }
  }

  return entries;
}

void AutorunAnalyzer::processWildcardPath(const std::string& disk_root,
                                          const std::string& path,
                                          std::vector<AutorunEntry>& results) {
  const size_t star_pos = path.find('*');
  const std::string base_path = path.substr(0, star_pos);
  const std::string search_path = disk_root + base_path;

  if (!std::filesystem::exists(search_path)) return;

  for (const auto& entry : std::filesystem::directory_iterator(search_path)) {
    if (entry.is_regular_file()) {
      results.push_back(createFilesystemEntry(entry.path(), path));
    }
  }
}

AutorunEntry AutorunAnalyzer::createFilesystemEntry(
    const std::filesystem::path& file_path, const std::string& location) {
  AutorunEntry entry;
  entry.name = file_path.filename().string();
  entry.path = file_path.string();
  entry.location = "Файловая система: " + location;
  return entry;
}

}
