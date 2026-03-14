/// @file security_context_analyzer.hpp
/// @brief Security Event Log analyzer for process launch context extraction.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/event_logs/ieventlog_collector.hpp"
#include "parsers/event_log/interfaces/iparser.hpp"

namespace WindowsDiskAnalysis {

/// @struct SecurityContextConfig
/// @brief Configuration for Security Event Log analysis.
struct SecurityContextConfig {
  bool enabled = true;  ///< Whether security context analysis is enabled.
  std::string security_log_path =
      "Windows/System32/winevt/Logs/Security.evtx";  ///< Path to the Security Event Log.
  std::vector<uint32_t>
      process_create_event_ids = {4688};  ///< Event IDs for process creation (e.g., 4688).
  std::vector<uint32_t> logon_event_ids = {4624};  ///< Event IDs for logon events (e.g., 4624).
  std::vector<uint32_t>
      privilege_event_ids = {4672};  ///< Event IDs for special privilege assignment (e.g., 4672).
  uint32_t logon_correlation_window_seconds =
      43200;  ///< Correlation window in seconds for 4688 <-> 4624/4672 pairing.
  uint32_t pid_correlation_window_seconds =
      3600;  ///< Correlation window in seconds for PID-based network event pairing.
};

/// @class SecurityContextAnalyzer
/// @brief Extracts "who launched what and with which privileges" from the Security Event Log.
///
/// @details Reads Security.evtx (or Security.evt), extracts events
/// @c 4688, @c 4624, @c 4672, and correlates them by @c LogonId, timestamp, and PID.
class SecurityContextAnalyzer final : public IEventLogCollector {
 public:
  /// @brief Constructs the security context analyzer.
  /// @param evt_parser  Parser for the legacy @c .evt format.
  /// @param evtx_parser Parser for the modern @c .evtx format.
  /// @param os_version  OS version string (from INI identifier), used for logging.
  /// @param ini_path    Path to @c config.ini.
  SecurityContextAnalyzer(
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
      std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
      std::string os_version, const std::string& ini_path);

  /// @brief Enriches @c process_data with security context from the Security Event Log.
  /// @param disk_root           Root path of the mounted Windows volume.
  /// @param process_data        Aggregated process map (updated in place).
  /// @param network_connections Network events used for PID-based process recovery.
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data,
               std::vector<NetworkConnection>& network_connections) override;

 private:
  /// @brief Loads the SecurityContext configuration from the INI file.
  /// @param ini_path Path to @c config.ini.
  void loadConfig(const std::string& ini_path);

  /// @brief Resolves the full path to the Security Event Log relative to the disk root.
  /// @param disk_root Root path of the mounted Windows volume.
  /// @return Full path to the Security Event Log, or an empty string on failure.
  [[nodiscard]] std::string resolveSecurityLogPath(
      const std::string& disk_root) const;

  /// @brief Selects the appropriate parser based on the log file extension.
  /// @param file_path Path to the @c .evt or @c .evtx file.
  /// @return Pointer to the matching parser, or @c nullptr if no match found.
  [[nodiscard]] EventLogAnalysis::IEventLogParser* getParserForFile(
      const std::string& file_path) const;

  std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser_;   ///< Parser for the legacy EVT format.
  std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser_;  ///< Parser for the modern EVTX format.
  std::string os_version_;          ///< Target OS version string.
  SecurityContextConfig config_;    ///< Active security context analysis configuration.
};

}  // namespace WindowsDiskAnalysis
