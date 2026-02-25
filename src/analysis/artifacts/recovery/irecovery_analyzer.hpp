/// @file irecovery_analyzer.hpp
/// @brief Базовый интерфейс для анализаторов восстановления артефактов

#pragma once

#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis {

/// @class IRecoveryAnalyzer
/// @brief Интерфейс анализатора, извлекающего восстановимые доказательства
class IRecoveryAnalyzer {
 public:
  virtual ~IRecoveryAnalyzer() noexcept = default;

  /// @brief Собирает восстановимые доказательства по подключенному диску
  /// @param disk_root Корень смонтированного Windows-раздела
  /// @return Набор восстановленных доказательств
  [[nodiscard]] virtual std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const = 0;
};

}  // namespace WindowsDiskAnalysis
