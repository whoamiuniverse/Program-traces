/// @file artifact_presence_tamper_detector.cpp
/// @brief Реализация ArtifactPresenceTamperDetector.
#include "artifact_presence_tamper_detector.hpp"

#include <filesystem>
#include <system_error>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::toLowerAscii;

namespace {

/// @brief Проверяет наличие Amcache.hve на диске.
/// @param disk_root Корень диска Windows.
/// @return true если файл отсутствует.
bool isAmcacheMissing(const std::string& disk_root) {
  // Проверяем оба известных пути: Vista+ и XP-era fallback
  const std::array<std::string_view, 2> candidates = {
      "Windows/appcompat/Programs/Amcache.hve",
      "Windows/AppCompat/Programs/Amcache.hve",
  };
  for (const auto rel : candidates) {
    const auto resolved =
        findPathCaseInsensitive(fs::path(disk_root) / std::string(rel));
    if (resolved.has_value()) return false;
  }
  return true;
}

/// @brief Проверяет, отключён ли USN Journal (файл журнала отсутствует).
/// @param disk_root Корень диска Windows.
/// @return true если журнал не найден ни по одному из стандартных путей.
bool isUsnJournalMissing(const std::string& disk_root) {
  const std::array<std::string_view, 4> candidates = {
      "$Extend/$UsnJrnl:$J",
      "$Extend/$UsnJrnl/$J",
      "$Extend/$UsnJrnl",
      "$UsnJrnl",
  };
  for (const auto rel : candidates) {
    const auto resolved =
        findPathCaseInsensitive(fs::path(disk_root) / std::string(rel));
    if (resolved.has_value()) return false;
  }
  return true;
}

/// @brief Проверяет, были ли удалены VSS-снимки.
/// @details Если директория "System Volume Information" присутствует, но в ней
/// нет ни одного файла/каталога с именем, соответствующим shadow copy
/// (содержит "harddiskvolumeshadowcopy" или начинается с '{'), то снимки
/// были удалены.
/// @param disk_root Корень диска Windows.
/// @return true если SVI присутствует, но снимки отсутствуют.
bool isVssDeleted(const std::string& disk_root) {
  const auto svi = findPathCaseInsensitive(fs::path(disk_root) /
                                           "System Volume Information");
  if (!svi.has_value()) return false;  // SVI нет — не можем судить

  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(
           *svi, fs::directory_options::skip_permission_denied, ec)) {
    if (ec) break;
    const std::string name_lower =
        toLowerAscii(entry.path().filename().string());
    if (name_lower.find("harddiskvolumeshadowcopy") != std::string::npos ||
        (!name_lower.empty() && name_lower.front() == '{')) {
      return false;  // нашли снимок
    }
  }
  return true;  // SVI есть, снимков нет
}

}  // namespace

void ArtifactPresenceTamperDetector::detect(
    const ExecutionEvidenceContext& ctx,
    std::vector<std::string>& global_tamper_flags) {
  if (!ctx.config.enable_artifact_presence_tamper_check) return;
  const auto logger = GlobalLogger::get();

  if (isAmcacheMissing(ctx.disk_root)) {
    appendTamperFlag(global_tamper_flags, "amcache_missing");
    logger->warn("Amcache.hve не обнаружен на диске");
  }

  if (isUsnJournalMissing(ctx.disk_root)) {
    appendTamperFlag(global_tamper_flags, "usn_journal_disabled");
    logger->warn("USN Journal ($UsnJrnl:$J) не обнаружен на диске");
  }

  if (isVssDeleted(ctx.disk_root)) {
    appendTamperFlag(global_tamper_flags, "volume_shadow_copies_deleted");
    logger->warn(
        "System Volume Information присутствует, но VSS-снимки отсутствуют");
  }
}

}  // namespace WindowsDiskAnalysis
