#pragma once

#include <map>
#include <memory>
#include <vector>

#include "../../../utils/config/config.hpp"
#include "../../../utils/export/csv_exporter.hpp"
#include "amcache/amcache_analyzer.hpp"  // Добавленный инклюд
#include "autorun/autorun_analyzer.hpp"
#include "logs/eventlog_analyzer.hpp"
#include "prefetch/prefetch_analyzer.hpp"

namespace WindowsDiskAnalysis {

class WindowsDiskAnalyzer {
 public:
  WindowsDiskAnalyzer(std::string  disk_root,
                      const std::string& config_path);
  void analyze(const std::string& output_path);

 private:
  void initializeComponents();
  void detectOSVersion();
  static void ensureDirectoryExists(const std::string& path);

  std::string disk_root_;
  std::string config_path_;
  OSInfo os_info_;

  std::unique_ptr<AutorunAnalyzer> autorun_analyzer_;
  std::unique_ptr<PrefetchAnalyzer> prefetch_analyzer_;
  std::unique_ptr<EventLogAnalyzer> eventlog_analyzer_;
  std::unique_ptr<AmcacheAnalyzer> amcache_analyzer_;  // Добавленный анализатор

  std::vector<AutorunEntry> autorun_entries_;
  std::map<std::string, ProcessInfo> process_data_;
  std::vector<NetworkConnection> network_connections_;
  std::vector<AmcacheEntry> amcache_entries_;  // Контейнер для результатов
};

}
