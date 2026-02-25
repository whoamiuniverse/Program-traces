/// @file usn_analyzer.hpp
/// @brief Анализатор источников восстановления USN/$LogFile

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class USNAnalyzer
/// @brief Извлекает кандидаты исполняемых файлов из USN/$LogFile
class USNAnalyzer final : public IRecoveryAnalyzer {
 public:
  explicit USNAnalyzer(std::string config_path);

  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  void loadConfiguration();

  std::string config_path_;
  bool enabled_ = true;
  bool enable_logfile_ = true;
  std::size_t binary_scan_max_mb_ = 64;
  std::size_t max_candidates_per_source_ = 2000;
};

}  // namespace WindowsDiskAnalysis
