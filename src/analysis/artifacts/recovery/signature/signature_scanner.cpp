/// @file signature_scanner.cpp
/// @brief Реализация SignatureScanner — поиск артефактов по бинарным сигнатурам.
#include "signature_scanner.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "analysis/artifacts/recovery/signature/signature_database.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::buildEvidenceDedupKey;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::toByteLimit;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

/// @brief Validates a Prefetch candidate: checks the SCCA version byte.
bool validatePrefetch(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  // Byte 4 from artifact start = format version (0x17, 0x1A, 0x1E, 0x1F)
  constexpr std::array<uint8_t, 4> kKnownVersions = {0x17, 0x1A, 0x1E, 0x1F};
  const std::size_t ver_offset = hit_offset + 4;
  if (ver_offset >= window.size()) return false;
  const uint8_t ver = window[ver_offset];
  return std::ranges::find(kKnownVersions, ver) != kKnownVersions.end();
}

/// @brief Validates a LNK candidate: checks that header size == 0x4C (76).
bool validateLnk(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  // Bytes 0-3 of LNK header are the HeaderSize field (LE), must equal 0x4C.
  if (hit_offset + 4 > window.size()) return false;
  const uint32_t header_size =
      static_cast<uint32_t>(window[hit_offset])        |
      (static_cast<uint32_t>(window[hit_offset + 1]) << 8) |
      (static_cast<uint32_t>(window[hit_offset + 2]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 3]) << 24);
  return header_size == 0x4C;
}

/// @brief Validates a PE candidate: checks that the PE offset is sane (< 4096).
bool validatePe(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  // Bytes 0x3C-0x3F of a PE DOS header contain the offset to the PE signature.
  if (hit_offset + 0x40 > window.size()) return false;
  const uint32_t pe_offset =
      static_cast<uint32_t>(window[hit_offset + 0x3C]) |
      (static_cast<uint32_t>(window[hit_offset + 0x3D]) << 8) |
      (static_cast<uint32_t>(window[hit_offset + 0x3E]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 0x3F]) << 24);
  return pe_offset > 0 && pe_offset < 4096;
}

/// @brief Returns true if the candidate passes artifact-specific structural checks.
bool validateCandidate(const ArtifactSignature& sig,
                       const std::vector<uint8_t>& window,
                       std::size_t hit_offset) {
  using namespace std::string_view_literals;
  if (sig.artifact_type == "Prefetch"sv) return validatePrefetch(window, hit_offset);
  if (sig.artifact_type == "LNK"sv)     return validateLnk(window, hit_offset);
  if (sig.artifact_type == "PE"sv)      return validatePe(window, hit_offset);
  return true;  // no structural check for other types — signature match is sufficient
}

/// @brief Searches for signature bytes inside a window, returns all match offsets.
std::vector<std::size_t> findSignatureOffsets(const std::vector<uint8_t>& window,
                                              const ArtifactSignature& sig) {
  std::vector<std::size_t> offsets;
  if (sig.byte_count == 0 || window.size() < sig.byte_count) return offsets;

  const std::size_t limit = window.size() - sig.byte_count;
  for (std::size_t i = 0; i <= limit; ++i) {
    if (std::memcmp(window.data() + i, sig.bytes, sig.byte_count) == 0) {
      // The hit is at position (i - sig.file_offset) in artifact coordinates.
      if (i >= sig.file_offset) {
        offsets.push_back(i - sig.file_offset);  // artifact start
      }
    }
  }
  return offsets;
}

/// @brief Formats a disk offset as a hex string for use in evidence details.
std::string formatOffset(uint64_t offset) {
  std::ostringstream ss;
  ss << "0x" << std::hex << std::uppercase << offset;
  return ss.str();
}

/// @brief Scans one file and appends matching evidence to @p results.
void scanFile(const fs::path& file_path,
              const std::string& source_label,
              std::size_t block_size,
              std::size_t max_bytes,
              std::size_t max_candidates,
              std::vector<RecoveryEvidence>& results,
              std::unordered_set<std::string>& dedup) {
  const auto logger = GlobalLogger::get();
  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SignatureScan: не удалось открыть \"{}\"", file_path.string());
    return;
  }

  // Overlap = max signature length - 1, so signatures spanning block boundaries
  // are always captured.
  constexpr std::size_t kMaxSigLen = 8;
  const std::size_t overlap = kMaxSigLen - 1;

  std::vector<uint8_t> buffer(block_size);
  std::vector<uint8_t> tail;  // tail of the previous block
  tail.reserve(overlap);

  std::size_t total_read = 0;
  uint64_t block_disk_offset = 0;
  std::size_t local_candidates = 0;

  while (total_read < max_bytes && local_candidates < max_candidates) {
    const std::size_t remaining = max_bytes - total_read;
    const std::size_t to_read = std::min(block_size, remaining);

    file.read(reinterpret_cast<char*>(buffer.data()),
              static_cast<std::streamsize>(to_read));
    const std::size_t n = static_cast<std::size_t>(file.gcount());
    if (n == 0) break;

    // Build search window: tail of previous block + current block.
    std::vector<uint8_t> window;
    window.reserve(tail.size() + n);
    window.insert(window.end(), tail.begin(), tail.end());
    window.insert(window.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));

    for (const auto& sig : SignatureDB::kSignatures) {
      if (local_candidates >= max_candidates) break;

      const auto offsets = findSignatureOffsets(window, sig);
      for (const std::size_t artifact_start : offsets) {
        if (local_candidates >= max_candidates) break;

        // Compute the actual disk offset of the artifact start.
        const uint64_t disk_offset =
            block_disk_offset +
            (artifact_start >= tail.size() ? artifact_start - tail.size() : 0);

        if (!validateCandidate(sig, window, artifact_start + sig.file_offset)) continue;

        RecoveryEvidence ev;
        ev.executable_path = std::string(sig.artifact_type) + "@" + formatOffset(disk_offset);
        ev.source          = source_label;
        ev.recovered_from  = std::string(sig.recovered_from);
        ev.details         = "file=" + file_path.filename().string() +
                             " offset=" + formatOffset(disk_offset) +
                             " type=" + std::string(sig.artifact_type);

        const std::string key = buildEvidenceDedupKey(ev);
        if (dedup.insert(key).second) {
          results.push_back(std::move(ev));
          ++local_candidates;
        }
      }
    }

    // Keep overlap for the next iteration.
    if (n >= overlap) {
      tail.assign(buffer.begin() + static_cast<std::ptrdiff_t>(n - overlap),
                  buffer.begin() + static_cast<std::ptrdiff_t>(n));
    } else {
      tail.insert(tail.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));
      if (tail.size() > overlap) {
        tail.erase(tail.begin(), tail.begin() +
                   static_cast<std::ptrdiff_t>(tail.size() - overlap));
      }
    }

    total_read += n;
    block_disk_offset += n;

    if (file.eof()) break;
  }

  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug,
              "SignatureScan: файл=\"{}\" прочитано={} КБ кандидатов={}",
              file_path.filename().string(), total_read / 1024, local_candidates);
}

}  // namespace

// ---------------------------------------------------------------------------
// SignatureScanner
// ---------------------------------------------------------------------------

SignatureScanner::SignatureScanner(std::string config_path,
                                   std::string image_path_override)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
  if (!image_path_override.empty()) {
    image_path_ = std::move(image_path_override);
  }
}

void SignatureScanner::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (!config.hasSection("Recovery")) return;

    auto readBool = [&](const std::string& key, bool def) {
      try { return config.getBool("Recovery", key, def); }
      catch (...) { return def; }
    };
    auto readInt = [&](const std::string& key, int def) {
      try { return config.getInt("Recovery", key, def); }
      catch (...) { return def; }
    };
    auto readStr = [&](const std::string& key, std::string def) {
      try { return config.getString("Recovery", key, def); }
      catch (...) { return def; }
    };

    enabled_        = readBool("EnableSignatureScan", enabled_);
    scan_pagefile_  = readBool("SignatureScanPagefile", scan_pagefile_);
    scan_hiberfil_  = readBool("SignatureScanHiberfil", scan_hiberfil_);
    image_path_     = readStr("SignatureScanPath", "");
    block_size_     = static_cast<std::size_t>(std::max(4096, readInt("SignatureScanBlockSizeKB", 64) * 1024));
    max_scan_mb_    = static_cast<std::size_t>(std::max(1, readInt("SignatureScanMaxMB", static_cast<int>(max_scan_mb_))));
    max_candidates_ = static_cast<std::size_t>(std::max(1, readInt("SignatureScanMaxCandidates", static_cast<int>(max_candidates_))));
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SignatureScanner: ошибка загрузки конфига: {}", e.what());
  }
}

std::vector<RecoveryEvidence> SignatureScanner::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug, "SignatureScan отключён в конфигурации");
    return {};
  }

  const std::size_t max_bytes = toByteLimit(max_scan_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;

  // 1. Explicit disk image
  if (!image_path_.empty()) {
    const auto resolved = findPathCaseInsensitive(fs::path(image_path_));
    if (resolved.has_value()) {
      logger->info("SignatureScan: сканирование образа \"{}\"", resolved->string());
      scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
               results, dedup);
    }
  }

  // 2. Pagefile / swapfile
  if (scan_pagefile_) {
    for (const auto rel :
         {"pagefile.sys", "swapfile.sys"}) {
      const auto resolved =
          findPathCaseInsensitive(fs::path(disk_root) / rel);
      if (!resolved.has_value()) continue;
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "SignatureScan: сканирование pagefile \"{}\"", resolved->string());
      scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
               results, dedup);
    }
  }

  // 3. Hibernation file
  if (scan_hiberfil_) {
    const auto resolved =
        findPathCaseInsensitive(fs::path(disk_root) / "hiberfil.sys");
    if (resolved.has_value()) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "SignatureScan: сканирование hiberfil \"{}\"", resolved->string());
      scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
               results, dedup);
    }
  }

  logger->info("Recovery(SignatureScan): total={}", results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
