#include "windows_disk_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "parsers/event_log/evt/parser/parser.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "analysis/os/os_detection.hpp"
#include "common/utils.hpp"

#ifdef __APPLE__
#include <sys/mount.h>
#endif

#ifdef __linux__
#include <mntent.h>
#endif

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;

namespace {

std::string ensureTrailingSlash(std::string path) {
  if (!path.empty() && path.back() != '/' && path.back() != '\\') {
    path.push_back('/');
  }
  return path;
}

std::string toLowerAscii(std::string text) {
  std::ranges::transform(text, text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

bool isAutoDiskRootValue(std::string value) {
  trim(value);
  const std::string lowered = toLowerAscii(std::move(value));
  return lowered.empty() || lowered == "auto";
}

std::string resolveMountedPath(const std::string& device_path) {
#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    if (device_path == mounts[i].f_mntfromname) {
      return mounts[i].f_mntonname;
    }
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (device_path == entry->mnt_fsname) {
        const std::string mount_point = entry->mnt_dir;
        endmntent(mounts_file);
        return mount_point;
      }
    }
    endmntent(mounts_file);
  }
#endif
  return {};
}

std::vector<std::string> listMountedRoots() {
  std::vector<std::string> roots;
  std::unordered_set<std::string> unique_roots;

  auto append_root = [&](const std::string& root_path_raw) {
    if (root_path_raw.empty()) return;
    const std::string root_path = ensureTrailingSlash(root_path_raw);
    std::error_code ec;
    if (!fs::is_directory(root_path, ec) || ec) return;
    if (unique_roots.insert(root_path).second) {
      roots.push_back(root_path);
    }
  };

#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    append_root(mounts[i].f_mntonname);
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (entry != nullptr && entry->mnt_dir != nullptr) {
        append_root(entry->mnt_dir);
      }
    }
    endmntent(mounts_file);
  }
#endif

  return roots;
}

std::string normalizeDiskRoot(std::string disk_root) {
  if (isAutoDiskRootValue(disk_root)) {
    return {};
  }

  std::error_code ec;
  if (fs::is_directory(disk_root, ec) && !ec) {
    return ensureTrailingSlash(std::move(disk_root));
  }

  ec.clear();
  const bool is_device = fs::is_block_file(disk_root, ec) ||
                         fs::is_character_file(disk_root, ec);
  if (is_device && !ec) {
    const std::string mount_point = resolveMountedPath(disk_root);
    if (mount_point.empty()) {
      throw std::runtime_error("устройство \"" + disk_root +
                               "\" не смонтировано");
    }
    return ensureTrailingSlash(mount_point);
  }

  ec.clear();
  if (!fs::exists(disk_root, ec) || ec) {
    throw std::runtime_error("путь \"" + disk_root + "\" не существует");
  }

  throw std::runtime_error(
      "ожидался путь к каталогу (точке монтирования) или блочному устройству");
}

std::string normalizePathSeparators(std::string path) {
  std::ranges::replace(path, '\\', '/');
  return path;
}

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) return std::nullopt;

  const fs::path relative = input_path.is_absolute()
                                ? input_path.relative_path()
                                : input_path;

  for (const fs::path& component_path : relative) {
    const std::string component = component_path.string();
    if (component.empty() || component == ".") continue;
    if (component == "..") {
      current = current.parent_path();
      continue;
    }

    const fs::path direct_candidate = current / component_path;
    ec.clear();
    if (fs::exists(direct_candidate, ec) && !ec) {
      current = direct_candidate;
      continue;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec || !fs::is_directory(current, ec)) {
      return std::nullopt;
    }

    const std::string component_lower = toLowerAscii(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;

      if (toLowerAscii(entry.path().filename().string()) == component_lower) {
        current = entry.path();
        matched = true;
        break;
      }
    }

    if (ec || !matched) return std::nullopt;
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) {
    return current;
  }
  return std::nullopt;
}

}  // namespace

WindowsDiskAnalyzer::WindowsDiskAnalyzer(std::string  disk_root,
                                         const std::string& config_path)
    : disk_root_(normalizeDiskRoot(std::move(disk_root))),
      config_path_(config_path) {
  const auto logger = GlobalLogger::get();

  if (disk_root_.empty()) {
    logger->info(
        "Корень анализа: auto (будет выполнен авто-поиск Windows-тома)");
  } else {
    logger->info("Корень анализа: \"{}\"", disk_root_);
  }
  logger->info("Загрузка конфигурации из файла: \"{}\"", config_path);
  detectOSVersion();
  initializeComponents();
}

void WindowsDiskAnalyzer::detectOSVersion() {
  Config config(config_path_);
  std::string initial_validation_error;

  if (disk_root_.empty()) {
    initial_validation_error =
        "корень анализа не задан (включен режим auto-поиска)";
  } else {
    try {
      validateRegistryHivePresence(config);
    } catch (const std::runtime_error& e) {
      initial_validation_error = e.what();
    }
  }

  if (!initial_validation_error.empty() &&
      !tryAutoSelectWindowsRoot(config, initial_validation_error)) {
    throw std::runtime_error(initial_validation_error +
                             " Авто-поиск Windows-раздела среди "
                             "смонтированных томов не дал результата.");
  }

  std::unique_ptr<RegistryAnalysis::IRegistryParser> registry_parser =
      std::make_unique<RegistryAnalysis::RegistryParser>();

  WindowsVersion::OSDetection detector((std::move(registry_parser)),
                                       (std::move(config)), disk_root_);
  os_info_ = detector.detect();
}

void WindowsDiskAnalyzer::validateRegistryHivePresence(
    const Config& config) const {
  std::vector<std::string> checked_paths;
  if (hasRegistryHivePresence(config, disk_root_, &checked_paths)) {
    return;
  }

  std::ostringstream error;
  error << "В корне \"" << disk_root_
        << "\" не найден ни один hive-файл из [OSInfoRegistryPaths]. "
           "Укажите смонтированный раздел Windows (не служебный том).";

  if (!checked_paths.empty()) {
    error << " Проверенные пути: ";
    for (size_t i = 0; i < checked_paths.size(); ++i) {
      if (i != 0) error << ", ";
      error << '"' << checked_paths[i] << '"';
    }
  }

  throw std::runtime_error(error.str());
}

bool WindowsDiskAnalyzer::hasRegistryHivePresence(
    const Config& config, const std::string& disk_root,
    std::vector<std::string>* checked_paths) const {
  if (checked_paths != nullptr) checked_paths->clear();
  if (disk_root.empty()) return false;

  const auto logger = GlobalLogger::get();
  const auto path_entries = config.getAllValues("OSInfoRegistryPaths");
  std::unordered_set<std::string> checked_paths_set;
  checked_paths_set.reserve(path_entries.size());

  for (const auto& [version_name, relative_path_raw] : path_entries) {
    std::string relative_path = normalizePathSeparators(relative_path_raw);
    trim(relative_path);
    if (relative_path.empty()) continue;

    const fs::path full_path = fs::path(disk_root) / relative_path;
    const std::string full_path_str = full_path.string();

    const bool is_new_path = checked_paths_set.insert(full_path_str).second;
    if (is_new_path && checked_paths != nullptr) {
      checked_paths->push_back(full_path_str);
    }

    if (const auto resolved = findPathCaseInsensitive(full_path);
        resolved.has_value()) {
      logger->debug("Найден hive-файл для определения ОС ({}): \"{}\"",
                    version_name, resolved->string());
      return true;
    }
  }

  return false;
}

bool WindowsDiskAnalyzer::tryAutoSelectWindowsRoot(
    const Config& config, const std::string& initial_check_error) {
  const auto logger = GlobalLogger::get();
  logger->warn("Проверка текущего корня анализа завершилась ошибкой: {}",
               initial_check_error);
  logger->info(
      "Запуск авто-поиска Windows-раздела среди смонтированных томов...");

  const std::vector<std::string> mounted_roots = listMountedRoots();
  if (mounted_roots.empty()) {
    logger->error("Авто-поиск не смог получить список смонтированных томов");
    return false;
  }

  std::string current_root = disk_root_;
  if (!current_root.empty()) {
    current_root = ensureTrailingSlash(std::move(current_root));
  }

  for (const auto& mount_root : mounted_roots) {
    if (!current_root.empty() && mount_root == current_root) continue;

    logger->debug("Проверка тома: \"{}\"", mount_root);
    if (hasRegistryHivePresence(config, mount_root, nullptr)) {
      disk_root_ = mount_root;
      logger->warn("Выбран Windows-раздел автоматически: \"{}\"", disk_root_);
      return true;
    }
  }

  logger->error(
      "Авто-поиск Windows-раздела завершился без результата (проверено томов: "
      "{})",
      mounted_roots.size());
  return false;
}

void WindowsDiskAnalyzer::initializeComponents() {
  // Инициализация парсеров
  auto registry_parser = std::make_unique<RegistryAnalysis::RegistryParser>();
  auto prefetch_parser = std::make_unique<PrefetchAnalysis::PrefetchParser>();
  auto evt_parser = std::make_unique<EventLogAnalysis::EvtParser>();
  auto evtx_parser = std::make_unique<EventLogAnalysis::EvtxParser>();

  // Создание анализаторов
  autorun_analyzer_ = std::make_unique<AutorunAnalyzer>(
      std::move(registry_parser), os_info_.ini_version, config_path_);

  prefetch_analyzer_ = std::make_unique<PrefetchAnalyzer>(
      std::move(prefetch_parser), os_info_.ini_version, config_path_);

  eventlog_analyzer_ = std::make_unique<EventLogAnalyzer>(
      std::move(evt_parser), std::move(evtx_parser), os_info_.ini_version,
      config_path_);

  // Добавленная инициализация AmcacheAnalyzer
  auto amcache_registry_parser =
      std::make_unique<RegistryAnalysis::RegistryParser>();
  amcache_analyzer_ = std::make_unique<AmcacheAnalyzer>(
      std::move(amcache_registry_parser), os_info_.ini_version, config_path_);
}

void WindowsDiskAnalyzer::ensureDirectoryExists(const std::string& path) {
  const fs::path dir_path = fs::path(path).parent_path();
  if (!dir_path.empty() && !exists(dir_path)) {
    create_directories(dir_path);
  }
}

void WindowsDiskAnalyzer::analyze(const std::string& output_path) {
  // 1. Сбор данных об автозагрузке
  autorun_entries_ = autorun_analyzer_->collect(disk_root_);

  // 2. Сбор данных из Amcache.hve (добавленный вызов)
  amcache_entries_ = amcache_analyzer_->collect(disk_root_);

  // 3. Сбор данных из Prefetch
  auto prefetch_results = prefetch_analyzer_->collect(disk_root_);
  for (auto& info : prefetch_results) {
    auto& merged = process_data_[info.filename];
    if (merged.filename.empty()) {
      merged.filename = info.filename;
    }
    merged.run_count += info.run_count;
    merged.run_times.insert(merged.run_times.end(), info.run_times.begin(),
                            info.run_times.end());
    merged.volumes.insert(merged.volumes.end(), info.volumes.begin(),
                          info.volumes.end());
    merged.metrics.insert(merged.metrics.end(), info.metrics.begin(),
                          info.metrics.end());
  }

  // 4. Анализ журналов событий
  eventlog_analyzer_->collect(disk_root_, process_data_, network_connections_);

  // 5. Экспорт результатов (обновленный вызов)
  ensureDirectoryExists(output_path);
  CSVExporter::exportToCSV(output_path, autorun_entries_, process_data_,
                           network_connections_,
                           amcache_entries_);  // Добавленный параметр
}
