#include "prefetch_analyzer.hpp"

#include <algorithm>
#include <atomic>
#include <future>
#include <iterator>
#include <optional>
#include <vector>

#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "analysis/os/os_detection.hpp"

namespace WindowsDiskAnalysis {

namespace {

const std::string kVersionDefaultsSection = "VersionDefaults";

std::string getConfigValueWithFallback(const Config& config,
                                       const std::string& version,
                                       const std::string& key) {
  if (config.hasKey(version, key)) {
    return config.getString(version, key, "");
  }

  if (config.hasKey(kVersionDefaultsSection, key)) {
    return config.getString(kVersionDefaultsSection, key, "");
  }

  return {};
}

bool hasPfExtensionCaseInsensitive(const std::filesystem::path& file_path) {
  const std::string extension = file_path.extension().string();
  return extension.size() == 3 && extension[0] == '.' &&
         (extension[1] == 'p' || extension[1] == 'P') &&
         (extension[2] == 'f' || extension[2] == 'F');
}

/// @brief Преобразует распарсенный Prefetch-объект в `ProcessInfo`.
/// @param prefetch_data Данные Prefetch из парсера.
/// @param fallback_path Путь к `.pf` для fallback имени процесса.
/// @return Нормализованная структура `ProcessInfo`.
ProcessInfo buildProcessInfoFromPrefetch(
    const PrefetchAnalysis::IPrefetchData& prefetch_data,
    const std::filesystem::path& fallback_path) {
  ProcessInfo info;

  const auto& run_times = prefetch_data.getRunTimes();
  info.run_times.reserve(run_times.size());
  for (const uint64_t run_time : run_times) {
    info.run_times.emplace_back(convert_run_times(run_time));
  }

  info.run_count = prefetch_data.getRunCount();
  info.filename = prefetch_data.getExecutableName();
  if (info.filename.empty()) {
    info.filename = fallback_path.stem().string();
  }
  info.volumes = prefetch_data.getVolumes();
  info.metrics = prefetch_data.getMetrics();
  return info;
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

  if (config.hasSection("Performance")) {
    enable_parallel_prefetch_ = config.getBool(
        "Performance", "EnableParallelPrefetch",
        config.getBool("Performance", "EnableParallelStages",
                       enable_parallel_prefetch_));
    worker_threads_ = static_cast<std::size_t>(std::max(
        1, config.getInt("Performance", "WorkerThreads",
                         static_cast<int>(worker_threads_))));
  }
}

std::vector<ProcessInfo> PrefetchAnalyzer::collect(
    const std::string& disk_root) {
  std::vector<ProcessInfo> results;
  const auto logger = GlobalLogger::get();

  // Проверяем наличие конфигурации для версии ОС
  const auto cfg_it = configs_.find(os_version_);
  if (cfg_it == configs_.end()) {
    logger->warn("Отсутствует конфигурация Prefetch для версии ОС: \"{}\"",
                 os_version_);
    return results;
  }

  const auto& cfg = cfg_it->second;
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
            PathUtils::findPathCaseInsensitive(std::filesystem::path(prefetch_path));
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

  std::vector<std::filesystem::path> prefetch_files;
  prefetch_files.reserve(512);
  for (const auto& entry :
       std::filesystem::directory_iterator(effective_prefetch_path)) {
    if (!hasPfExtensionCaseInsensitive(entry.path())) continue;
    prefetch_files.push_back(entry.path());
  }

  const std::size_t total_files = prefetch_files.size();
  results.reserve(total_files);

  std::size_t processed_count = 0;
  if (enable_parallel_prefetch_ && worker_threads_ > 1 &&
      total_files > 1) {
    const std::size_t workers =
        std::min<std::size_t>(worker_threads_, total_files);
    const std::size_t expected_per_worker =
        (total_files + workers - 1) / workers;
    std::atomic<std::size_t> next_index{0};
    std::vector<std::future<std::vector<ProcessInfo>>> futures;
    futures.reserve(workers);

    for (std::size_t worker = 0; worker < workers; ++worker) {
      futures.push_back(std::async(std::launch::async, [&]() {
        PrefetchAnalysis::PrefetchParser local_parser;
        std::vector<ProcessInfo> worker_results;
        worker_results.reserve(expected_per_worker);

        while (true) {
          const std::size_t index =
              next_index.fetch_add(1, std::memory_order_relaxed);
          if (index >= total_files) break;
          const std::filesystem::path& file_path = prefetch_files[index];

          try {
            auto prefetch_data = local_parser.parse(file_path.string());
            worker_results.push_back(
                buildProcessInfoFromPrefetch(*prefetch_data, file_path));
          } catch (const std::exception& e) {
            logger->warn("Файл Prefetch пропущен из-за ошибки");
            logger->debug("Ошибка анализа Prefetch \"{}\": {}", file_path.string(),
                          e.what());
          }
        }
        return worker_results;
      }));
    }

    for (auto& future : futures) {
      auto worker_results = future.get();
      processed_count += worker_results.size();
      results.insert(results.end(),
                     std::make_move_iterator(worker_results.begin()),
                     std::make_move_iterator(worker_results.end()));
    }
  } else {
    // Последовательный режим: один parser object.
    for (const auto& file_path : prefetch_files) {
      try {
        auto prefetch_data = parser_->parse(file_path.string());
        results.push_back(buildProcessInfoFromPrefetch(*prefetch_data, file_path));
        processed_count++;
      } catch (const std::exception& e) {
        logger->warn("Файл Prefetch пропущен из-за ошибки");
        logger->debug("Ошибка анализа Prefetch \"{}\": {}", file_path.string(),
                      e.what());
      }
    }
  }

  logger->info("Проанализировано \"{}\" Prefetch-файлов, найдено \"{}\" процессов",
               processed_count, results.size());
  return results;
}

}
