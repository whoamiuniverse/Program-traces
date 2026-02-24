#include "prefetch_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string_view>

#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "analysis/os/os_detection.hpp"

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

std::string toLowerAscii(std::string text) {
  std::ranges::transform(text, text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) return std::nullopt;

  const fs::path relative =
      input_path.is_absolute() ? input_path.relative_path() : input_path;

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

PrefetchAnalyzer::PrefetchAnalyzer(
    std::unique_ptr<PrefetchAnalysis::IPrefetchParser> parser,
    std::string os_version, const std::string& ini_path)
    : parser_(std::move(parser)), os_version_(std::move(os_version)) {
  loadConfigurations(ini_path);
}

void PrefetchAnalyzer::loadConfigurations(const std::string& ini_path) {
  Config config(ini_path, false, false);
  const auto logger = GlobalLogger::get();

  // Получаем список поддерживаемых версий
  std::string versions_str = config.getString("General", "Versions", "");
  auto versions = split(versions_str, ',');

  for (auto& version : versions) {
    trim(version);
    if (version.empty()) continue;

    PrefetchConfig cfg;

    // Загрузка пути к папке Prefetch
    std::string path = getConfigValueWithFallback(config, version, "PrefetchPath");
    trim(path);
    if (!path.empty()) {
      std::ranges::replace(path, '\\', '/');
      cfg.prefetch_path = path;
    }

    configs_[version] = cfg;
    logger->debug(
        "Загружена конфигурация Prefetch для \"{}\": путь = \"{}\"", version,
        cfg.prefetch_path.empty() ? "по умолчанию" : cfg.prefetch_path);
  }
}

std::vector<ProcessInfo> PrefetchAnalyzer::collect(
    const std::string& disk_root) {
  std::vector<ProcessInfo> results;
  const auto logger = GlobalLogger::get();

  // Проверяем наличие конфигурации для версии ОС
  if (!configs_.contains(os_version_)) {
    logger->warn("Отсутствует конфигурация Prefetch для версии ОС: \"{}\"",
                 os_version_);
    return results;
  }

  const auto& cfg = configs_[os_version_];
  if (cfg.prefetch_path.empty()) {
    logger->warn("Путь к Prefetch не настроен");
    logger->debug("Версия ОС без PrefetchPath: \"{}\"", os_version_);
    return results;
  }

  std::string prefetch_path = disk_root + cfg.prefetch_path;
  std::filesystem::path effective_prefetch_path(prefetch_path);

  // Проверяем существование директории
  if (!std::filesystem::exists(effective_prefetch_path)) {
    if (const auto resolved =
            findPathCaseInsensitive(std::filesystem::path(prefetch_path));
        resolved.has_value()) {
      effective_prefetch_path = *resolved;
      logger->debug("Путь Prefetch разрешён case-insensitive: \"{}\" -> \"{}\"",
                    prefetch_path, effective_prefetch_path.string());
    } else {
      logger->warn("Папка Prefetch не найдена");
      logger->debug("Проверенный путь Prefetch: \"{}\"", prefetch_path);
      return results;
    }
  }

  // Обрабатываем все .pf файлы
  size_t processed_count = 0;
  for (const auto& entry :
       std::filesystem::directory_iterator(effective_prefetch_path)) {
    const std::string ext_lower =
        toLowerAscii(entry.path().extension().string());
    if (ext_lower != ".pf") continue;

    try {
      auto prefetch_data = parser_->parse(entry.path().string());

      ProcessInfo info;

      for (const auto& run_time : prefetch_data->getRunTimes()) {
        auto time = convert_run_times(run_time);
        info.run_times.emplace_back(time);
      }

      info.run_count = prefetch_data->getRunCount();
      info.filename = prefetch_data->getExecutableName();
      if (info.filename.empty()) {
        info.filename = entry.path().stem().string();
      }
      info.volumes = prefetch_data->getVolumes();
      info.metrics = prefetch_data->getMetrics();

      // Сохраняем в результаты
      results.emplace_back(info);
      processed_count++;
    } catch (const std::exception& e) {
      logger->warn("Файл Prefetch пропущен из-за ошибки");
      logger->debug("Ошибка анализа Prefetch \"{}\": {}", entry.path().string(),
                    e.what());
    }
  }

  logger->info(
      "Проанализировано \"{}\" Prefetch-файлов, найдено \"{}\" процессов",
      processed_count, results.size());
  return results;
}

}
