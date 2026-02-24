#include "prefetch_analyzer.hpp"

#include "../../../../utils/config/config.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../os_detection/os_detection.hpp"

namespace WindowsDiskAnalysis {

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
    std::string path = config.getString(version, "PrefetchPath", "");
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
  std::string prefetch_path = disk_root + cfg.prefetch_path;

  // Проверяем существование директории
  if (!std::filesystem::exists(prefetch_path)) {
    logger->warn("Папка Prefetch не найдена: \"{}\"", prefetch_path);
    return results;
  }

  // Обрабатываем все .pf файлы
  size_t processed_count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(prefetch_path)) {
    if (entry.path().extension() != ".pf") continue;

    try {
      auto prefetch_data = parser_->parse(entry.path().string());

      ProcessInfo info;

      for (const auto& run_time : prefetch_data->getRunTimes()) {
        auto time = convert_run_times(run_time);
        info.run_times.emplace_back(time);
      }

      info.run_count = prefetch_data->getRunCount();
      info.filename = prefetch_data->getExecutableName();
      info.volumes = prefetch_data->getVolumes();
      info.metrics = prefetch_data->getMetrics();

      // Сохраняем в результаты
      results.emplace_back(info);
      processed_count++;
    } catch (const std::exception& e) {
      logger->warn("Ошибка анализа файла \"{}\": \"{}\"", entry.path().string(),
                   e.what());
    }
  }

  logger->info(
      "Проанализировано \"{}\" Prefetch-файлов, найдено \"{}\" процессов",
      processed_count, results.size());
  return results;
}

}
