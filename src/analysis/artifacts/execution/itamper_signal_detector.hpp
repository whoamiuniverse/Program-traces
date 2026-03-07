/// @file itamper_signal_detector.hpp
/// @brief ISP-интерфейс детектора глобальных tamper-сигналов.
#pragma once

#include <string>
#include <vector>

#include "analysis/artifacts/execution/execution_evidence_context.hpp"

namespace WindowsDiskAnalysis {

/// @class ITamperSignalDetector
/// @brief Интерфейс детектора глобальных признаков фальсификации артефактов.
/// @details Реализация работает только с глобальными флагами и не изменяет
/// агрегированные данные процессов.
class ITamperSignalDetector {
 public:
  /// @brief Виртуальный деструктор базового интерфейса.
  virtual ~ITamperSignalDetector() = default;

  /// @brief Обнаруживает tamper-сигналы и добавляет флаги.
  /// @param ctx Неизменяемый контекст анализа.
  /// @param global_tamper_flags Выходной вектор глобальных флагов без дублей.
  virtual void detect(const ExecutionEvidenceContext& ctx,
                      std::vector<std::string>& global_tamper_flags) = 0;
};

}  // namespace WindowsDiskAnalysis
