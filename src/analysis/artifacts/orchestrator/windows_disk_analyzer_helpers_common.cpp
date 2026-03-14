/// @file windows_disk_analyzer_helpers_common.cpp
/// @brief Базовые helper-функции оркестратора (строки, токены, merge, логирование).

#include "windows_disk_analyzer_helpers.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

#if defined(__APPLE__) || defined(__linux__)
#include <unistd.h>
#endif

namespace WindowsDiskAnalysis::Orchestrator::Detail {

namespace fs = std::filesystem;

std::string ensureTrailingSlash(std::string path) {
  if (!path.empty() && path.back() != '/' && path.back() != '\\') {
    path.push_back('/');
  }
  return path;
}

std::string toLowerAscii(std::string text) {
  return to_lower(std::move(text));
}

void appendUniqueToken(std::vector<std::string>& target, std::string token) {
  trim(token);
  if (token.empty()) return;

  const std::string lowered = toLowerAscii(token);
  const bool already_exists = std::ranges::any_of(
      target, [&](const std::string& current) {
        return toLowerAscii(current) == lowered;
      });
  if (!already_exists) {
    target.push_back(std::move(token));
  }
}

void appendTamperFlag(ProcessInfo& info, const std::string& flag) {
  appendUniqueToken(info.tamper_flags, flag);
}

void appendEvidenceSource(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.evidence_sources, source);
}

void appendTimelineArtifact(ProcessInfo& info, const std::string& artifact) {
  appendUniqueToken(info.timeline_artifacts, artifact);
}

void appendRecoveredFrom(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.recovered_from, source);
}

bool isAutoDiskRootValue(std::string value) {
  trim(value);
  const std::string lowered = toLowerAscii(std::move(value));
  return lowered.empty() || lowered == "auto";
}

bool isAccessDeniedError(const std::error_code& ec) {
  return ec == std::errc::permission_denied ||
         ec == std::errc::operation_not_permitted;
}

bool containsAccessDenied(std::string_view message) {
  std::string lowered(message);
  lowered = toLowerAscii(std::move(lowered));
  return lowered.find("доступ запрещен") != std::string::npos ||
         lowered.find("доступ запрещён") != std::string::npos ||
         lowered.find("permission denied") != std::string::npos ||
         lowered.find("operation not permitted") != std::string::npos;
}

std::string formatFilesystemError(const std::error_code& ec) {
  if (!ec) return {};
  if (isAccessDeniedError(ec)) {
    return "доступ запрещен (" + ec.message() + ')';
  }
  return ec.message();
}

std::string formatDeviceLabel(const std::string& device_path) {
  if (device_path.empty()) return "unknown";
  const fs::path device(device_path);
  const std::string filename = device.filename().string();
  return filename.empty() ? device_path : filename;
}

bool isServerLikeValue(const std::string& value) {
  const std::string lowered = toLowerAscii(value);
  return lowered.find("server") != std::string::npos;
}

std::string normalizePathSeparators(std::string path) {
  return PathUtils::normalizePathSeparators(std::move(path));
}

ScopedDebugLevelOverride::ScopedDebugLevelOverride(const bool debug_enabled) {
  if (debug_enabled) return;

  logger_ = GlobalLogger::get();
  previous_level_ = logger_->level();
  if (previous_level_ <= spdlog::level::debug) {
    logger_->set_level(spdlog::level::info);
    active_ = true;
  }
}

ScopedDebugLevelOverride::~ScopedDebugLevelOverride() {
  if (active_ && logger_ != nullptr) {
    logger_->set_level(previous_level_);
  }
}

std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path,
                                                std::string* error_reason) {
  return PathUtils::findPathCaseInsensitive(input_path, error_reason);
}

std::string formatWindowsLabel(const WindowsRootSummary& summary) {
  const std::string& name =
      summary.mapped_name.empty() ? summary.product_name : summary.mapped_name;
  if (summary.build.empty()) return name;
  return name + " (build " + summary.build + ")";
}

void mergeRecoveryEvidenceToProcessData(
    const std::vector<RecoveryEvidence>& recovery_entries,
    std::unordered_map<std::string, ProcessInfo>& process_data) {
  for (const auto& evidence : recovery_entries) {
    std::string executable_path = evidence.executable_path;
    trim(executable_path);
    if (executable_path.empty()) continue;

    auto& info = process_data[executable_path];
    if (info.filename.empty()) {
      info.filename = executable_path;
    }

    appendEvidenceSource(info,
                         evidence.source.empty() ? "Recovery" : evidence.source);
    appendRecoveredFrom(
        info, evidence.recovered_from.empty() ? evidence.source
                                              : evidence.recovered_from);

    if (!evidence.timestamp.empty()) {
      info.run_times.push_back(evidence.timestamp);
      if (EvidenceUtils::isTimestampLike(evidence.timestamp)) {
        EvidenceUtils::updateTimestampMin(info.first_seen_utc, evidence.timestamp);
        EvidenceUtils::updateTimestampMax(info.last_seen_utc, evidence.timestamp);
      }
    }

    if (!evidence.tamper_flag.empty()) {
      appendTamperFlag(info, evidence.tamper_flag);
    }

    std::string timeline = "[" + (evidence.source.empty() ? "Recovery"
                                                          : evidence.source) +
                           "]";
    if (!evidence.timestamp.empty()) {
      timeline = evidence.timestamp + " " + timeline;
    }
    if (!evidence.details.empty()) {
      timeline += " " + evidence.details;
    }
    appendTimelineArtifact(info, timeline);
  }
}

bool hasInteractiveStdin() {
#if defined(__APPLE__) || defined(__linux__)
  return isatty(fileno(stdin)) != 0;
#else
  return true;
#endif
}

}  // namespace WindowsDiskAnalysis::Orchestrator::Detail
