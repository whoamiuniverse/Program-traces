#include "autorun_analyzer.hpp"

#include <string_view>
#include <utility>

#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "common/utils.hpp"

namespace WindowsDiskAnalysis {
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

std::string extractExecutablePath(std::string command) {
  trim(command);
  if (command.empty()) return {};

  if (command.front() == '"' || command.front() == '\'') {
    const char quote = command.front();
    const size_t end_quote = command.find(quote, 1);
    if (end_quote != std::string::npos) {
      return command.substr(1, end_quote - 1);
    }
    return command.substr(1);
  }

  const size_t separator = command.find_first_of(" \t");
  if (separator == std::string::npos) return command;
  return command.substr(0, separator);
}

}  // namespace

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
    std::string reg_path =
        getConfigValueWithFallback(config, version, "RegistryPath");
    trim(reg_path);
    if (!reg_path.empty()) {
      std::ranges::replace(reg_path, '\\', '/');
      cfg.registry_path = reg_path;
    }

    // Загрузка ключей реестра
    std::string reg_keys =
        getConfigValueWithFallback(config, version, "RegistryKeys");
    auto reg_key_list = split(reg_keys, ',');
    for (auto& key : reg_key_list) {
      trim(key);
      if (key.empty()) continue;
      std::ranges::replace(key, '\\', '/');
      cfg.registry_locations.push_back(key);
    }

    // Загрузка путей файловой системы
    std::string fs_paths =
        getConfigValueWithFallback(config, version, "FilesystemPaths");
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
    logger->warn("Файл куста реестра автозапуска не найден");
    logger->debug("Путь к кусту реестра автозапуска: \"{}\"", full_reg_path);
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

        // Извлечение исполняемого файла из командной строки
        entry.path = extractExecutablePath(entry.command);
        trim(entry.path);

        if (!entry.path.empty()) {
          entries.push_back(std::move(entry));
        }
      }
    } catch (const std::exception& e) {
      logger->warn("Пропущен ключ автозапуска в реестре");
      logger->debug("Ключ автозапуска \"{}\" пропущен: {}", location, e.what());
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

        if (!std::filesystem::exists(full_path)) continue;

        if (const std::filesystem::path target_path(full_path);
            std::filesystem::is_regular_file(target_path)) {
          entries.push_back(createFilesystemEntry(full_path, path));
        } else if (std::filesystem::is_directory(target_path)) {
          for (const auto& entry :
               std::filesystem::directory_iterator(target_path)) {
            if (!entry.is_regular_file()) continue;
            entries.push_back(createFilesystemEntry(entry.path(), path));
          }
        }
      }
    } catch (const std::exception& e) {
      logger->warn("Пропущен путь автозапуска в файловой системе");
      logger->debug("Путь ФС \"{}\" пропущен: {}", path, e.what());
    }
  }

  return entries;
}

void AutorunAnalyzer::processWildcardPath(const std::string& disk_root,
                                          const std::string& path,
                                          std::vector<AutorunEntry>& results) {
  namespace fs = std::filesystem;

  const size_t star_pos = path.find('*');
  const std::string base_path = path.substr(0, star_pos);
  std::string suffix_path = path.substr(star_pos + 1);
  trim(suffix_path);
  if (!suffix_path.empty() &&
      (suffix_path.front() == '/' || suffix_path.front() == '\\')) {
    suffix_path.erase(suffix_path.begin());
  }

  const fs::path search_path = fs::path(disk_root) / base_path;

  if (!std::filesystem::exists(search_path)) return;

  for (const auto& entry : std::filesystem::directory_iterator(search_path)) {
    if (!entry.is_directory()) continue;

    fs::path candidate = entry.path();
    if (!suffix_path.empty()) {
      candidate /= suffix_path;
    }

    if (!fs::exists(candidate)) continue;

    if (fs::is_regular_file(candidate)) {
      results.push_back(createFilesystemEntry(candidate, path));
      continue;
    }

    if (fs::is_directory(candidate)) {
      for (const auto& nested : fs::directory_iterator(candidate)) {
        if (!nested.is_regular_file()) continue;
        results.push_back(createFilesystemEntry(nested.path(), path));
      }
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
