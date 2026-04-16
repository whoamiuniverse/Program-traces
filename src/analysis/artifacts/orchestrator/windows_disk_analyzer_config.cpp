/// @file windows_disk_analyzer_config.cpp
/// @brief Загрузка секций конфигурации для оркестратора анализа.

#include "windows_disk_analyzer.hpp"

#include <cstddef>
#include <exception>
#include <string>
#include <thread>

#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

namespace WindowsDiskAnalysis {

void WindowsDiskAnalyzer::loadLoggingOptions(const Config& config) {
  const auto logger = GlobalLogger::get();

  if (!config.hasSection("Logging")) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "Секция [Logging] не найдена, используются настройки debug по "
        "умолчанию");
    return;
  }

  auto readFlag = [&](const std::string& key, bool current_value) {
    try {
      return config.getBool("Logging", key, current_value);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Logging]/{}", key);
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Logging]/{}: {}", key, e.what());
      return current_value;
    }
  };

  debug_options_.os_detection =
      readFlag("DebugOSDetection", debug_options_.os_detection);
  debug_options_.autorun = readFlag("DebugAutorun", debug_options_.autorun);
  debug_options_.prefetch = readFlag("DebugPrefetch", debug_options_.prefetch);
  debug_options_.eventlog = readFlag("DebugEventLog", debug_options_.eventlog);
  debug_options_.amcache = readFlag("DebugAmcache", debug_options_.amcache);
  debug_options_.execution = readFlag("DebugExecution", debug_options_.execution);
  debug_options_.recovery = readFlag("DebugRecovery", debug_options_.recovery);

  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
      "Загружены настройки [Logging]: OSDetection={}, Autorun={}, "
      "Prefetch={}, EventLog={}, Amcache={}, Execution={}, Recovery={}",
      debug_options_.os_detection, debug_options_.autorun,
      debug_options_.prefetch, debug_options_.eventlog, debug_options_.amcache,
      debug_options_.execution, debug_options_.recovery);
}

void WindowsDiskAnalyzer::loadPerformanceOptions(const Config& config) {
  const auto logger = GlobalLogger::get();

  if (!config.hasSection("Performance")) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
        "Секция [Performance] не найдена, используются значения по умолчанию");
    return;
  }

  auto readBool = [&](const std::string& key, const bool current_value) {
    try {
      return config.getBool("Performance", key, current_value);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Performance]/{}", key);
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Performance]/{}: {}", key, e.what());
      return current_value;
    }
  };

  auto readSize = [&](const std::string& key, const std::size_t current_value,
                      const std::size_t min_value) {
    try {
      const int raw =
          config.getInt("Performance", key, static_cast<int>(current_value));
      if (raw < static_cast<int>(min_value)) {
        return current_value;
      }
      return static_cast<std::size_t>(raw);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Performance]/{}", key);
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Performance]/{}: {}", key, e.what());
      return current_value;
    }
  };

  const std::size_t hardware_threads = std::max<std::size_t>(
      1, static_cast<std::size_t>(std::thread::hardware_concurrency()));
  performance_options_.enable_parallel_stages = readBool(
      "EnableParallelStages", performance_options_.enable_parallel_stages);
  performance_options_.worker_threads =
      readSize("WorkerThreads",
               std::min(performance_options_.worker_threads, hardware_threads), 1);
  performance_options_.max_io_workers =
      readSize("MaxIOWorkers", performance_options_.max_io_workers, 1);

  if (performance_options_.worker_threads > hardware_threads) {
    performance_options_.worker_threads = hardware_threads;
  }
  if (performance_options_.max_io_workers >
      performance_options_.worker_threads) {
    performance_options_.max_io_workers = performance_options_.worker_threads;
  }

  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, 
      "Загружены настройки [Performance]: EnableParallelStages={}, "
      "WorkerThreads={}, MaxIOWorkers={}",
      performance_options_.enable_parallel_stages,
      performance_options_.worker_threads, performance_options_.max_io_workers);
}

}  // namespace WindowsDiskAnalysis
