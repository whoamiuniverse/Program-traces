/// @file vss_analyzer.hpp
/// @brief Анализатор источников восстановления VSS/Pagefile/Memory

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class VSSAnalyzer
/// @brief Извлекает кандидаты исполняемых файлов из VSS и volatile-источников
class VSSAnalyzer final : public IRecoveryAnalyzer {
 public:
  explicit VSSAnalyzer(std::string config_path);

  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  void loadConfiguration();

  std::string config_path_;
  bool enabled_ = true;
  bool enable_pagefile_ = true;
  bool enable_memory_ = true;
  bool enable_unallocated_ = true;
  std::size_t binary_scan_max_mb_ = 64;
  std::size_t max_candidates_per_source_ = 2000;
  std::string unallocated_image_path_;
};

}  // namespace WindowsDiskAnalysis
