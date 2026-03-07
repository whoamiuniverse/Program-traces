/// @file security_log_tamper_detector.hpp
/// @brief Детектор фальсификации журнала Security.evtx.
#pragma once
#include <string>
#include <vector>
#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class SecurityLogTamperDetector
/// @brief Проверяет журнал Security.evtx на наличие событий очистки (ID 1102).
class SecurityLogTamperDetector final : public ITamperSignalDetector {
 public:
  void detect(const ExecutionEvidenceContext& ctx,
              std::vector<std::string>& global_tamper_flags) override;
};

}  // namespace WindowsDiskAnalysis
