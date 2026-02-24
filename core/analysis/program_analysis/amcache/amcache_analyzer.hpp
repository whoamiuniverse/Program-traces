#pragma once

#include <memory>
#include <string>
#include <vector>

#include "../../../../parsers/registry/parser/parser.hpp"
#include "../data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

struct AmcacheConfig {
  std::string amcache_path;               ///< Путь к Amcache.hve
  std::vector<std::string> amcache_keys;  ///< Ключи для анализа в Amcache
};

/// @brief Анализатор Amcache.hve для извлечения информации о запущенных
/// программах
class AmcacheAnalyzer {
 public:
  AmcacheAnalyzer(std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
                  std::string os_version, std::string ini_path);

  std::vector<AmcacheEntry> collect(const std::string& disk_root) const;

 private:
  void loadConfiguration();
  static AmcacheEntry processInventoryApplicationEntry(
      const std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>>&
          values);

  std::unique_ptr<RegistryAnalysis::IRegistryParser> parser_;
  std::string os_version_;
  std::string ini_path_;
  std::string amcache_path_;
  std::vector<std::string> amcache_keys_;
};

}
