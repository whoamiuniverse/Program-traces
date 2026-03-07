/// @file ieventlog_collector.hpp
/// @brief Базовый интерфейс для анализаторов журналов событий Windows

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @class IEventLogCollector
/// @brief Общий контракт для сборщиков данных из журналов событий
///
/// @details Унифицирует сигнатуру `collect()` для EventLogAnalyzer
/// и SecurityContextAnalyzer, позволяя оркестратору работать с ними
/// через единый полиморфный интерфейс (DIP / LSP).
class IEventLogCollector {
 public:
  virtual ~IEventLogCollector() noexcept = default;

  /// @brief Обогащает агрегированные данные сведениями из журналов событий
  /// @param disk_root   Корень смонтированного Windows-раздела
  /// @param process_data        Карта процессов (обновляется на месте)
  /// @param network_connections Сетевые события (может дополняться или читаться)
  virtual void collect(const std::string& disk_root,
                       std::unordered_map<std::string, ProcessInfo>& process_data,
                       std::vector<NetworkConnection>& network_connections) = 0;
};

}  // namespace WindowsDiskAnalysis
