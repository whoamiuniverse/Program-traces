/// @file eventlog_analyzer.hpp
/// @brief Windows Event Log analyzer for process and network event extraction.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/event_logs/ieventlog_collector.hpp"
#include "infra/config/config.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"

namespace WindowsDiskAnalysis {

/// @struct EventLogConfig
/// @brief Configuration parameters for Windows Event Log analysis.
struct EventLogConfig {
  std::vector<std::string> log_paths;       ///< Paths to Event Log files.
  std::vector<uint32_t> process_event_ids;  ///< Event IDs related to process creation.
  std::vector<uint32_t>
      network_event_ids;  ///< Event IDs related to network connections.
};

/// @class EventLogAnalyzer
/// @brief Analyzer that extracts process and network data from Windows Event Logs.
///
/// @details Supports both legacy EVT and modern EVTX formats.
/// Optionally processes log files in parallel across worker threads.
class EventLogAnalyzer final : public IEventLogCollector {
 public:
  /// @brief Constructs the Event Log analyzer.
  /// @param evt_parser  Parser for the legacy EVT format.
  /// @param evtx_parser Parser for the modern EVTX format.
  /// @param os_version  Target OS version string used for configuration lookup.
  /// @param ini_path    Path to the INI configuration file.
  EventLogAnalyzer(
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
      std::string os_version, const std::string& ini_path);

  /// @brief Collects process and network data from Windows Event Logs.
  /// @param disk_root           Root path of the analyzed disk.
  /// @param process_data        Map of processes to populate (updated in place).
  /// @param network_connections Vector of network connections to populate.
  /// @throws ParsingException   On errors opening or reading Event Log files.
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data,
               std::vector<NetworkConnection>& network_connections) override;

 private:
  /// @brief Loads per-OS-version configuration from the INI file.
  /// @param ini_path Path to the INI configuration file.
  void loadConfigurations(const std::string& ini_path);

  /// @brief Selects the appropriate parser based on the log file extension.
  /// @param file_path Path to the Event Log file.
  /// @return Pointer to the matching parser, or @c nullptr if no match found.
  [[nodiscard]] EventLogAnalysis::IEventLogParser* getParserForFile(
      const std::string& file_path) const;

  /// @brief Loads performance options from the @c [Performance] INI section.
  /// @param config Application configuration object.
  void loadPerformanceOptions(const Config& config);

  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evt_parser_;  ///< Parser for the legacy EVT format.
  std::unique_ptr<EventLogAnalysis::IEventLogParser>
      evtx_parser_;  ///< Parser for the modern EVTX format.
  std::map<std::string, EventLogConfig>
      configs_;             ///< Per-OS-version analyzer configurations.
  std::string os_version_;  ///< Target OS version string.
  bool enable_parallel_eventlog_ = false;  ///< Whether parallel log processing is enabled.
  std::size_t worker_threads_ =
      std::max<std::size_t>(1, std::thread::hardware_concurrency());  ///< Number of worker threads.
};

}  // namespace WindowsDiskAnalysis
