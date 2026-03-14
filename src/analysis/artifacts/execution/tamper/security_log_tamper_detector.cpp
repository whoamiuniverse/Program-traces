/// @file security_log_tamper_detector.cpp
/// @brief Реализация SecurityLogTamperDetector.
#include "security_log_tamper_detector.hpp"

#include <filesystem>
#include <string>

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;

void SecurityLogTamperDetector::detect(const ExecutionEvidenceContext& ctx,
                                       std::vector<std::string>& global_tamper_flags) {
  if (!ctx.config.enable_security_log_tamper_check) return;
  const auto logger = GlobalLogger::get();

  const fs::path security_log = fs::path(ctx.disk_root) / ctx.config.security_log_path;
  const auto resolved = findPathCaseInsensitive(security_log);
  if (!resolved.has_value()) return;

  try {
    EventLogAnalysis::EvtxParser parser;
    auto events = parser.getEventsByType(resolved->string(), 1102);
    if (!events.empty()) {
      appendTamperFlag(global_tamper_flags, "security_log_cleared");
      logger->warn("Обнаружены события очистки журнала Security (ID 1102)");
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Проверка security_log_cleared пропущена: {}", e.what());
  }
}

}  // namespace WindowsDiskAnalysis
