/// @file ieventlog_collector.hpp
/// @brief Base interface for Windows Event Log collectors.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @class IEventLogCollector
/// @brief Common contract for collectors that extract data from Windows Event Logs.
///
/// @details Unifies the @c collect() signature for @c EventLogAnalyzer
/// and @c SecurityContextAnalyzer, enabling the orchestrator to work
/// with them through a single polymorphic interface (DIP / LSP).
class IEventLogCollector {
 public:
  /// @brief Virtual destructor for safe polymorphic deletion.
  virtual ~IEventLogCollector() noexcept = default;

  /// @brief Enriches aggregated data with information from Event Logs.
  /// @param disk_root           Root path of the mounted Windows partition.
  /// @param process_data        Map of processes to enrich (updated in place).
  /// @param network_connections Network events vector (may be extended or read).
  virtual void collect(const std::string& disk_root,
                       std::unordered_map<std::string, ProcessInfo>& process_data,
                       std::vector<NetworkConnection>& network_connections) = 0;
};

}  // namespace WindowsDiskAnalysis
