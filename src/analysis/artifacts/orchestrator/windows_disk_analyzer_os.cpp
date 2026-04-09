/// @file windows_disk_analyzer_os.cpp
/// @brief Логика выбора Windows-тома и определения версии ОС.

#include "windows_disk_analyzer.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <unordered_set>
#include <vector>

#include "analysis/os/os_detection.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

namespace {

struct BestEffortRunConfig {
  bool enable = false;
  std::string fallback_ini_version = "Windows10";
};

std::string resolveFirstConfiguredVersion(const Config& config) {
  std::string versions = config.getString("General", "Versions", "");
  for (auto& version : split(versions, ',')) {
    trim(version);
    if (!version.empty()) {
      return version;
    }
  }
  return {};
}

BestEffortRunConfig loadBestEffortRunConfig(const Config& config) {
  BestEffortRunConfig options;

  try {
    options.enable =
        config.getBool("General", "EnableBestEffortRun", options.enable);
  } catch (...) {
  }

  try {
    options.fallback_ini_version = config.getString(
        "General", "FallbackOSVersion", options.fallback_ini_version);
    trim(options.fallback_ini_version);
  } catch (...) {
  }

  if (options.fallback_ini_version.empty()) {
    options.fallback_ini_version = resolveFirstConfiguredVersion(config);
    if (options.fallback_ini_version.empty()) {
      options.fallback_ini_version = "Windows10";
    }
  }

  return options;
}

bool canUseBestEffortFallback(const std::string& disk_root) {
  if (disk_root.empty()) {
    return false;
  }

  std::error_code ec;
  return fs::exists(fs::path(disk_root), ec) && !ec;
}

void applyBestEffortFallback(OSInfo& os_info,
                             const BestEffortRunConfig& options,
                             const std::string& reason) {
  const auto logger = GlobalLogger::get();

  os_info = {};
  os_info.ini_version = options.fallback_ini_version;
  os_info.product_name = "Windows (best-effort)";
  os_info.fullname_os = "Windows (best-effort, ini=" + os_info.ini_version + ")";

  logger->warn("OS detection недоступен, используется best-effort профиль \"{}\"",
               os_info.ini_version);
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug,
              "Best-effort fallback reason: {}", reason);
}

}  // namespace

void WindowsDiskAnalyzer::detectOSVersion() {
  Config config(config_path_);
  loadLoggingOptions(config);
  loadPerformanceOptions(config);
  loadTamperOptions(config);
  const BestEffortRunConfig best_effort = loadBestEffortRunConfig(config);
  std::string initial_validation_error;

  if (disk_root_.empty()) {
    initial_validation_error =
        "корень анализа не задан (включен режим auto-поиска)";
  } else {
    try {
      ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
      validateRegistryHivePresence(config);
    } catch (const DiskAnalyzerException& e) {
      initial_validation_error = e.what();
    }
  }

  if (!initial_validation_error.empty()) {
    ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
    if (!tryAutoSelectWindowsRoot(config, initial_validation_error)) {
      if (best_effort.enable && canUseBestEffortFallback(disk_root_)) {
        applyBestEffortFallback(os_info_, best_effort,
                                "auto-select failed: " +
                                    initial_validation_error);
        return;
      }
      throw WindowsVolumeSelectionException(initial_validation_error);
    }
  }

  std::unique_ptr<RegistryAnalysis::IRegistryParser> registry_parser =
      std::make_unique<RegistryAnalysis::RegistryParser>();

  WindowsVersion::OSDetection detector((std::move(registry_parser)),
                                       (std::move(config)), disk_root_);
  try {
    ScopedDebugLevelOverride scoped_debug(debug_options_.os_detection);
    os_info_ = detector.detect();
  } catch (const std::exception& e) {
    if (best_effort.enable && canUseBestEffortFallback(disk_root_)) {
      applyBestEffortFallback(os_info_, best_effort,
                              std::string("os detection failed: ") + e.what());
      return;
    }
    throw;
  }
}

void WindowsDiskAnalyzer::validateRegistryHivePresence(
    const Config& config) const {
  const auto logger = GlobalLogger::get();
  std::vector<std::string> checked_paths;
  std::vector<std::string> checked_errors;
  if (hasRegistryHivePresence(config, disk_root_, &checked_paths,
                              &checked_errors)) {
    return;
  }

  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Проверка hive-файлов для корня \"{}\" не прошла", disk_root_);
  if (!checked_paths.empty()) {
    std::ostringstream checked;
    for (size_t i = 0; i < checked_paths.size(); ++i) {
      if (i != 0) checked << ", ";
      checked << '"' << checked_paths[i] << '"';
    }
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Проверенные пути hive: {}", checked.str());
  } else {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Проверенные пути hive отсутствуют в конфигурации");
  }

  if (!checked_errors.empty()) {
    const auto first_access_error = std::ranges::find_if(
        checked_errors, [](const std::string& error) {
          return containsAccessDenied(error);
        });
    if (first_access_error != checked_errors.end()) {
      logger->warn("Ошибка доступа к файловой системе при проверке hive");
    }
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибки проверки путей hive: {}",
                  checked_errors.front());
  }

  throw RegistryHiveValidationException(disk_root_);
}

bool WindowsDiskAnalyzer::hasRegistryHivePresence(
    const Config& config, const std::string& disk_root,
    std::vector<std::string>* checked_paths,
    std::vector<std::string>* checked_errors) const {
  if (checked_paths != nullptr) checked_paths->clear();
  if (checked_errors != nullptr) checked_errors->clear();
  if (disk_root.empty()) return false;

  const auto logger = GlobalLogger::get();
  const auto hive_candidates = collectRegistryHiveCandidates(config);
  std::unordered_set<std::string> checked_paths_set;
  checked_paths_set.reserve(hive_candidates.size());

  for (const auto& [version_name, relative_path] : hive_candidates) {
    if (relative_path.empty()) continue;

    const fs::path full_path = fs::path(disk_root) / relative_path;
    const std::string full_path_str = full_path.string();

    const bool is_new_path = checked_paths_set.insert(full_path_str).second;
    if (is_new_path && checked_paths != nullptr) {
      checked_paths->push_back(full_path_str);
    }

    std::string resolve_error;
    if (const auto resolved = findPathCaseInsensitive(full_path, &resolve_error);
        resolved.has_value()) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Найден hive-файл для определения ОС ({}): \"{}\"",
                    version_name, resolved->string());
      return true;
    }

    if (checked_errors != nullptr && !resolve_error.empty()) {
      checked_errors->push_back(full_path_str + " -> " + resolve_error);
    }
  }

  return false;
}

bool WindowsDiskAnalyzer::tryAutoSelectWindowsRoot(
    const Config& config, const std::string& initial_check_error) {
  const auto logger = GlobalLogger::get();
  logger->warn("Выбранный корень анализа не подходит, запускается авто-поиск");
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Причина переключения в режим авто-поиска: {}",
                initial_check_error);
  logger->info("Запуск авто-поиска Windows-раздела...");

  const std::vector<MountedRootInfo> mounted_roots = listMountedRoots();
  if (mounted_roots.empty()) {
    logger->error("Не удалось получить список смонтированных томов");
    return false;
  }

  std::string current_root = disk_root_;
  if (!current_root.empty()) {
    current_root = ensureTrailingSlash(std::move(current_root));
  }

  std::vector<AutoSelectCandidate> candidates;
  std::size_t access_denied_mounts = 0;

  for (const auto& mount : mounted_roots) {
    if (!current_root.empty() && mount.mount_root == current_root) continue;

    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Проверка тома: \"{}\" ({})", mount.mount_root,
                  formatDeviceLabel(mount.device_path));

    std::vector<std::string> mount_errors;
    if (!hasRegistryHivePresence(config, mount.mount_root, nullptr,
                                 &mount_errors)) {
      if (std::ranges::any_of(mount_errors, [](const std::string& error) {
            return containsAccessDenied(error);
          })) {
        access_denied_mounts++;
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Том \"{}\" пропущен из-за ограничения доступа",
                      mount.mount_root);
      }
      continue;
    }

    std::string summary_error;
    std::string os_label = "Windows (версия не определена)";
    if (const auto summary =
            detectWindowsRootSummary(config, mount.mount_root, &summary_error);
        summary.has_value()) {
      os_label = formatWindowsLabel(*summary);
    } else if (!summary_error.empty()) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Не удалось определить версию ОС для \"{}\": {}",
                    mount.mount_root, summary_error);
    }

    candidates.push_back({mount, os_label});
  }

  if (candidates.empty()) {
    logger->error("Авто-поиск Windows-раздела не дал результата");
    if (access_denied_mounts > 0) {
      logger->warn("При авто-поиске нет доступа к {} томам",
                   access_denied_mounts);
    }
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Авто-поиск проверил {} смонтированных томов",
                  mounted_roots.size());
    return false;
  }

  if (candidates.size() == 1) {
    disk_root_ = candidates.front().mount.mount_root;
    logger->info("Windows-раздел выбран автоматически: \"{}\" ({}, {})",
                 disk_root_, formatDeviceLabel(candidates.front().mount.device_path),
                 candidates.front().os_label);
    return true;
  }

  std::cout << "\nНайдено несколько Windows-разделов. Выберите нужный:\n";
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    const auto& candidate = candidates[i];
    std::cout << (i + 1) << ". " << formatDeviceLabel(candidate.mount.device_path)
              << ", " << candidate.os_label
              << ", путь: " << candidate.mount.mount_root << '\n';
  }

  std::size_t selected_index = 0;
  if (!hasInteractiveStdin()) {
    logger->warn(
        "Запуск без интерактивной консоли; выбран первый найденный "
        "Windows-раздел");
  } else {
    while (true) {
      std::cout << "Введите номер [1-" << candidates.size() << "]: " << std::flush;
      std::string input;
      if (!std::getline(std::cin, input)) {
        logger->warn(
            "Не удалось прочитать выбор пользователя; выбран первый найденный "
            "Windows-раздел");
        break;
      }

      trim(input);
      uint32_t selected_number = 0;
      if (tryParseUInt32(input, selected_number) && selected_number >= 1 &&
          selected_number <= candidates.size()) {
        selected_index = static_cast<std::size_t>(selected_number - 1);
        break;
      }
      std::cout << "Некорректный выбор. Укажите число от 1 до "
                << candidates.size() << ".\n";
    }
  }

  const auto& selected = candidates[selected_index];
  disk_root_ = selected.mount.mount_root;
  logger->info("Выбран Windows-раздел: \"{}\" ({}, {})", disk_root_,
               formatDeviceLabel(selected.mount.device_path), selected.os_label);
  return true;
}


}  // namespace WindowsDiskAnalysis
