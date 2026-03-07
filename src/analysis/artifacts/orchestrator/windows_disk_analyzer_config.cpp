/// @file windows_disk_analyzer_config.cpp
/// @brief Загрузка секций конфигурации для оркестратора анализа.

#include "windows_disk_analyzer.hpp"

#include <cstddef>
#include <exception>
#include <string>
#include <thread>
#include <vector>

#include "infra/logging/logger.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

void WindowsDiskAnalyzer::loadLoggingOptions(const Config& config) {
  const auto logger = GlobalLogger::get();

  if (!config.hasSection("Logging")) {
    logger->debug(
        "Секция [Logging] не найдена, используются настройки debug по "
        "умолчанию");
    return;
  }

  auto readFlag = [&](const std::string& key, bool current_value) {
    try {
      return config.getBool("Logging", key, current_value);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Logging]/{}", key);
      logger->debug("Ошибка чтения [Logging]/{}: {}", key, e.what());
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

  logger->debug(
      "Загружены настройки [Logging]: OSDetection={}, Autorun={}, "
      "Prefetch={}, EventLog={}, Amcache={}, Execution={}, Recovery={}",
      debug_options_.os_detection, debug_options_.autorun,
      debug_options_.prefetch, debug_options_.eventlog, debug_options_.amcache,
      debug_options_.execution, debug_options_.recovery);
}

void WindowsDiskAnalyzer::loadPerformanceOptions(const Config& config) {
  const auto logger = GlobalLogger::get();

  if (!config.hasSection("Performance")) {
    logger->debug(
        "Секция [Performance] не найдена, используются значения по умолчанию");
    return;
  }

  auto readBool = [&](const std::string& key, const bool current_value) {
    try {
      return config.getBool("Performance", key, current_value);
    } catch (const std::exception& e) {
      logger->warn("Некорректный параметр [Performance]/{}", key);
      logger->debug("Ошибка чтения [Performance]/{}: {}", key, e.what());
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
      logger->debug("Ошибка чтения [Performance]/{}: {}", key, e.what());
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

  logger->debug(
      "Загружены настройки [Performance]: EnableParallelStages={}, "
      "WorkerThreads={}, MaxIOWorkers={}",
      performance_options_.enable_parallel_stages,
      performance_options_.worker_threads, performance_options_.max_io_workers);
}


CSVExportOptions WindowsDiskAnalyzer::loadCSVExportOptions() const {
  const auto logger = GlobalLogger::get();

  CSVExportOptions options;
  Config config(config_path_);

  auto readSizeOption = [&](const std::string& section, const std::string& key,
                            const std::size_t current_value) {
    try {
      const int value = config.getInt(section, key, static_cast<int>(current_value));
      if (value < 0) {
        logger->warn(
            "Параметр [{}/{}] не может быть отрицательным ({}), "
            "оставлено значение {}",
            section, key, value, current_value);
        return current_value;
      }
      return static_cast<std::size_t>(value);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [{}/{}] ({}), оставлено значение {}",
          section, key, e.what(), current_value);
      return current_value;
    }
  };

  auto readBoolOption = [&](const std::string& section, const std::string& key,
                            bool current_value) {
    try {
      return config.getBool(section, key, current_value);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [{}/{}] ({}), оставлено значение {}",
          section, key, e.what(), current_value);
      return current_value;
    }
  };

  auto readListOption = [&](const std::string& section, const std::string& key,
                            const std::vector<std::string>& current_value) {
    try {
      if (!config.hasKey(section, key)) return current_value;
      const std::string raw = config.getString(section, key, "");
      return parseListSetting(raw);
    } catch (const std::exception& e) {
      logger->warn(
          "Не удалось прочитать [{}/{}] ({}), оставлено значение по "
          "умолчанию",
          section, key, e.what());
      return current_value;
    }
  };

  if (config.hasSection("CSVExport")) {
    options.max_metric_names =
        readSizeOption("CSVExport", "MetricMaxNames", options.max_metric_names);
    options.metric_skip_prefixes = readListOption(
        "CSVExport", "MetricSkipPrefixes", options.metric_skip_prefixes);
    options.metric_skip_contains = readListOption(
        "CSVExport", "MetricSkipContains", options.metric_skip_contains);
    options.metric_skip_exact =
        readListOption("CSVExport", "MetricSkipExact", options.metric_skip_exact);
    options.drop_short_upper_tokens = readBoolOption(
        "CSVExport", "DropShortUpperTokens", options.drop_short_upper_tokens);
    options.short_upper_token_max_length = readSizeOption(
        "CSVExport", "ShortUpperTokenMaxLength",
        options.short_upper_token_max_length);
    options.drop_hex_like_tokens = readBoolOption(
        "CSVExport", "DropHexLikeTokens", options.drop_hex_like_tokens);
    options.hex_like_min_length = readSizeOption(
        "CSVExport", "HexLikeMinLength", options.hex_like_min_length);
    options.drop_upper_alnum_tokens = readBoolOption(
        "CSVExport", "DropUpperAlnumTokens", options.drop_upper_alnum_tokens);
    options.upper_alnum_min_length = readSizeOption(
        "CSVExport", "UpperAlnumMinLength", options.upper_alnum_min_length);
  } else {
    logger->debug(
        "Секция [CSVExport] не найдена, используются значения по умолчанию");
  }

  if (config.hasSection("TamperRules")) {
    options.tamper_rule_prefetch_missing_enabled = readBoolOption(
        "TamperRules", "EnablePrefetchMissingRule",
        options.tamper_rule_prefetch_missing_enabled);
    options.tamper_rule_prefetch_missing_require_process_image =
        readBoolOption("TamperRules", "PrefetchMissingRequireProcessImage",
                       options.tamper_rule_prefetch_missing_require_process_image);
    options.tamper_prefetch_missing_runtime_sources = readListOption(
        "TamperRules", "PrefetchMissingRuntimeSources",
        options.tamper_prefetch_missing_runtime_sources);
    options.tamper_rule_amcache_deleted_trace_enabled = readBoolOption(
        "TamperRules", "EnableAmcacheDeletedTraceRule",
        options.tamper_rule_amcache_deleted_trace_enabled);
    options.tamper_rule_registry_inconsistency_enabled = readBoolOption(
        "TamperRules", "EnableRegistryInconsistencyRule",
        options.tamper_rule_registry_inconsistency_enabled);
    options.tamper_registry_only_sources = readListOption(
        "TamperRules", "RegistryOnlySources",
        options.tamper_registry_only_sources);
    options.tamper_registry_strong_sources = readListOption(
        "TamperRules", "RegistryStrongSources",
        options.tamper_registry_strong_sources);
  }

  logger->debug(
      "Загружены настройки CSV/Tamper: MetricMaxNames={}, Prefixes={}, "
      "Contains={}, Exact={}",
      options.max_metric_names, options.metric_skip_prefixes.size(),
      options.metric_skip_contains.size(), options.metric_skip_exact.size());

  return options;
}


}  // namespace WindowsDiskAnalysis
