/// @file recovery_utils.cpp
/// @brief Реализация общих утилит recovery-анализаторов.

#include "analysis/artifacts/recovery/recovery_utils.hpp"

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"

namespace WindowsDiskAnalysis::RecoveryUtils {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;

}  // namespace

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::findPathCaseInsensitive
std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) return input_path;

  fs::path current = input_path.is_absolute() ? input_path.root_path()
                                              : fs::current_path(ec);
  if (ec) return std::nullopt;

  const fs::path relative = input_path.is_absolute()
                                ? input_path.relative_path()
                                : input_path;

  for (const fs::path& component_path : relative) {
    const std::string component = component_path.string();
    if (component.empty() || component == ".") continue;
    if (component == "..") {
      current = current.parent_path();
      continue;
    }

    const fs::path direct = current / component_path;
    ec.clear();
    if (fs::exists(direct, ec) && !ec) {
      current = direct;
      continue;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec || !fs::is_directory(current, ec) ||
        ec) {
      return std::nullopt;
    }

    const std::string lowered = toLowerAscii(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;
      if (toLowerAscii(entry.path().filename().string()) == lowered) {
        current = entry.path();
        matched = true;
        break;
      }
    }

    if (ec || !matched) {
      return std::nullopt;
    }
  }

  ec.clear();
  if (fs::exists(current, ec) && !ec) return current;
  return std::nullopt;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::toByteLimit
std::size_t toByteLimit(const std::size_t megabytes) {
  constexpr std::size_t kMegabyte = 1024 * 1024;
  if (megabytes == 0) return kMegabyte;
  return megabytes * kMegabyte;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::scanRecoveryFileBinary
std::vector<RecoveryEvidence> scanRecoveryFileBinary(
    const fs::path& file_path, const std::string& source,
    const std::string& recovered_from, const std::size_t max_bytes,
    const std::size_t max_candidates) {
  std::vector<RecoveryEvidence> results;
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value()) return results;

  const auto candidates =
      extractExecutableCandidatesFromBinary(*data_opt, max_candidates);
  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(fs::last_write_time(file_path, ec));

  results.reserve(candidates.size());
  for (const auto& executable : candidates) {
    RecoveryEvidence evidence;
    evidence.executable_path = executable;
    evidence.source = source;
    evidence.recovered_from = recovered_from;
    evidence.timestamp = timestamp;
    evidence.details = file_path.filename().string();
    results.push_back(std::move(evidence));
  }
  return results;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::buildEvidenceDedupKey
std::string buildEvidenceDedupKey(const RecoveryEvidence& evidence) {
  return toLowerAscii(evidence.executable_path) + "|" +
         toLowerAscii(evidence.source) + "|" +
         toLowerAscii(evidence.recovered_from) + "|" + evidence.timestamp + "|" +
         toLowerAscii(evidence.details);
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::appendUniqueEvidence
void appendUniqueEvidence(std::vector<RecoveryEvidence>& target,
                          std::vector<RecoveryEvidence>& source,
                          std::unordered_set<std::string>& dedup_keys) {
  for (auto& evidence : source) {
    const std::string key = buildEvidenceDedupKey(evidence);
    if (!dedup_keys.insert(key).second) continue;
    target.push_back(std::move(evidence));
  }
}

}  // namespace WindowsDiskAnalysis::RecoveryUtils
