/// @file registry_state_tamper_detector.cpp
/// @brief Реализация RegistryStateTamperDetector.
#include "registry_state_tamper_detector.hpp"

#include <exception>
#include <string>

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;

namespace {

/// @brief Читает DWORD-значение из SYSTEM hive по пути относительно control set.
/// @param parser      Инициализированный парсер реестра.
/// @param hive_path   Абсолютный путь к SYSTEM hive.
/// @param cs_root     Разрешённый корень control set (например "ControlSet001").
/// @param subpath     Путь к ключу/значению относительно cs_root.
/// @return Значение DWORD или std::nullopt, если ключ/значение не найдено.
std::optional<uint32_t> readDword(RegistryAnalysis::RegistryParser& parser,
                                  const std::string& hive_path,
                                  const std::string& cs_root,
                                  const std::string& subpath) {
  try {
    const std::string full_path = cs_root + "/" + subpath;
    auto value = parser.getSpecificValue(hive_path, full_path);
    if (!value) return std::nullopt;
    return value->getAsDword();
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

}  // namespace

void RegistryStateTamperDetector::detect(
    const ExecutionEvidenceContext& ctx,
    std::vector<std::string>& global_tamper_flags) {
  if (!ctx.config.enable_registry_state_tamper_check) return;
  if (ctx.system_hive_path.empty()) return;

  const auto logger = GlobalLogger::get();

  try {
    RegistryAnalysis::RegistryParser parser;
    const std::string cs_root =
        resolveControlSetRoot(parser, ctx.system_hive_path, "CurrentControlSet");

    // EnablePrefetcher == 0 означает, что Prefetch отключён вручную.
    // Значения: 0=disabled, 1=app prefetch, 2=boot prefetch, 3=both (default).
    constexpr std::string_view kPrefetchParamsKey =
        "Control/Session Manager/Memory Management/PrefetchParameters/"
        "EnablePrefetcher";
    const auto enable_prefetcher =
        readDword(parser, ctx.system_hive_path, cs_root, std::string(kPrefetchParamsKey));
    if (enable_prefetcher.has_value() && *enable_prefetcher == 0) {
      appendTamperFlag(global_tamper_flags, "prefetch_disabled");
      logger->warn("Обнаружено отключение Prefetch (EnablePrefetcher=0)");
    }

    // EventLog\Start != 2 (SERVICE_AUTO_START) означает, что служба журналов
    // событий не запускается автоматически — возможная антифорензика.
    constexpr std::string_view kEventLogStartKey = "Services/EventLog/Start";
    const auto event_log_start =
        readDword(parser, ctx.system_hive_path, cs_root, std::string(kEventLogStartKey));
    if (event_log_start.has_value() && *event_log_start != 2) {
      appendTamperFlag(global_tamper_flags, "event_log_service_disabled");
      logger->warn("Обнаружено изменение типа запуска службы EventLog (Start={})",
                   *event_log_start);
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "RegistryStateTamperDetector: ошибка чтения SYSTEM hive: {}",
                e.what());
  }
}

}  // namespace WindowsDiskAnalysis
