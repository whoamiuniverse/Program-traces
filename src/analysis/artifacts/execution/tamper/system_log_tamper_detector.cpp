/// @file system_log_tamper_detector.cpp
/// @brief Реализация SystemLogTamperDetector.
#include "system_log_tamper_detector.hpp"

#include <filesystem>

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;

void SystemLogTamperDetector::detect(const ExecutionEvidenceContext& ctx,
                                     std::vector<std::string>& global_tamper_flags) {
  if (!ctx.config.enable_system_log_tamper_check) return;
  const auto logger = GlobalLogger::get();

  const fs::path system_log = fs::path(ctx.disk_root) / ctx.config.system_log_path;
  const auto resolved = findPathCaseInsensitive(system_log);
  if (!resolved.has_value()) return;

  try {
    EventLogAnalysis::EvtxParser parser;
    auto events = parser.getEventsByType(resolved->string(), 104);
    if (!events.empty()) {
      appendTamperFlag(global_tamper_flags, "system_log_cleared");
      logger->warn("Обнаружены события очистки журнала System (ID 104)");
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Проверка system_log_cleared пропущена: {}", e.what());
  }
}

}  // namespace WindowsDiskAnalysis
