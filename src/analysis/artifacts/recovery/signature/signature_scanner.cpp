/// @file signature_scanner.cpp
/// @brief Реализация SignatureScanner — поиск артефактов по бинарным сигнатурам.
#include "signature_scanner.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
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
// Structural validators
// ---------------------------------------------------------------------------

namespace {

/// @brief Validates a Prefetch candidate: checks the SCCA version byte.
bool validatePrefetch(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  constexpr std::array<uint8_t, 4> kKnownVersions = {0x17, 0x1A, 0x1E, 0x1F};
  const std::size_t ver_offset = hit_offset + 4;
  if (ver_offset >= window.size()) return false;
  const uint8_t ver = window[ver_offset];
  return std::ranges::find(kKnownVersions, ver) != kKnownVersions.end();
}

/// @brief Validates a LNK candidate: checks that header size == 0x4C (76).
bool validateLnk(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  if (hit_offset + 4 > window.size()) return false;
  const uint32_t header_size =
      static_cast<uint32_t>(window[hit_offset])         |
      (static_cast<uint32_t>(window[hit_offset + 1]) << 8)  |
      (static_cast<uint32_t>(window[hit_offset + 2]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 3]) << 24);
  return header_size == 0x4C;
}

/// @brief Validates a PE candidate: checks that the PE offset is sane (< 4096).
bool validatePe(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  if (hit_offset + 0x40 > window.size()) return false;
  const uint32_t pe_offset =
      static_cast<uint32_t>(window[hit_offset + 0x3C]) |
      (static_cast<uint32_t>(window[hit_offset + 0x3D]) << 8)  |
      (static_cast<uint32_t>(window[hit_offset + 0x3E]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 0x3F]) << 24);
  return pe_offset > 0 && pe_offset < 4096;
}

/// @brief Validates an EVTX chunk: checks chunk size field == 65536.
/// Layout: magic(8), first_event_record_number(8), last_event_record_number(8),
///         log_file_offset(8), last_event_record_offset(8), next_record_offset(4),
///         last_event_record_identifier(8), header_size(4), last_chunk_number(2),
///         ... chunk_data_length(4) at offset 0x28.
bool validateEvtxChunk(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  // Minimum size: 0x80 bytes (128)
  if (hit_offset + 0x80 > window.size()) return false;
  // chunk_data_length at offset 0x28 relative to chunk start should be <= 65536
  const uint32_t data_len =
      static_cast<uint32_t>(window[hit_offset + 0x28]) |
      (static_cast<uint32_t>(window[hit_offset + 0x29]) << 8)  |
      (static_cast<uint32_t>(window[hit_offset + 0x2A]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 0x2B]) << 24);
  return data_len <= 65536 && data_len >= 512;
}

/// @brief Validates an NTFS hive-bin chunk: checks size field is a multiple of 4096.
/// hbin layout: magic(4), offset(4), size(4).
bool validateHbin(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  if (hit_offset + 12 > window.size()) return false;
  const uint32_t size =
      static_cast<uint32_t>(window[hit_offset + 8])  |
      (static_cast<uint32_t>(window[hit_offset + 9])  << 8)  |
      (static_cast<uint32_t>(window[hit_offset + 10]) << 16) |
      (static_cast<uint32_t>(window[hit_offset + 11]) << 24);
  // hive-bin sizes are multiples of 4096 and typically 4096–65536.
  return size >= 4096 && size <= 0x40000 && (size % 4096 == 0);
}

/// @brief Validates a Task Scheduler 1.0 .job file: checks Reserved1 == 0 at offset 8.
bool validateJobFile(const std::vector<uint8_t>& window, std::size_t hit_offset) {
  // ProductVersion=0x0400(2), FileVersion=0x0001(2), Reserved1=0(2) at offset+8
  if (hit_offset + 10 > window.size()) return false;
  const uint16_t reserved1 =
      static_cast<uint16_t>(window[hit_offset + 8]) |
      (static_cast<uint16_t>(window[hit_offset + 9]) << 8);
  return reserved1 == 0x0000;
}

/// @brief Returns true if the candidate passes artifact-specific structural checks.
bool validateCandidate(const ArtifactSignature& sig,
                       const std::vector<uint8_t>& window,
                       std::size_t hit_offset) {
  using namespace std::string_view_literals;
  if (sig.artifact_type == "Prefetch"sv)  return validatePrefetch(window, hit_offset);
  if (sig.artifact_type == "LNK"sv)       return validateLnk(window, hit_offset);
  if (sig.artifact_type == "PE"sv)        return validatePe(window, hit_offset);
  if (sig.artifact_type == "EVTXChunk"sv) return validateEvtxChunk(window, hit_offset);
  if (sig.artifact_type == "HiveBin"sv)   return validateHbin(window, hit_offset);
  if (sig.artifact_type == "JobFile"sv)   return validateJobFile(window, hit_offset);
  return true;
}

/// @brief Searches for signature bytes inside a window, returns all match offsets.
std::vector<std::size_t> findSignatureOffsets(const std::vector<uint8_t>& window,
                                              const ArtifactSignature& sig) {
  std::vector<std::size_t> offsets;
  if (sig.byte_count == 0 || window.size() < sig.byte_count) return offsets;

  const std::size_t limit = window.size() - sig.byte_count;
  for (std::size_t i = 0; i <= limit; ++i) {
    if (std::memcmp(window.data() + i, sig.bytes, sig.byte_count) == 0) {
      if (i >= sig.file_offset)
        offsets.push_back(i - sig.file_offset);
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

// ---------------------------------------------------------------------------
// Shannon entropy analysis (1.2.6)
// ---------------------------------------------------------------------------

/// @brief Computes the Shannon entropy of a byte block (0.0 – 8.0 bits/byte).
/// High entropy (> 7.2) typically indicates encryption or compression.
double computeShannon(const uint8_t* data, std::size_t len) {
  if (len == 0) return 0.0;
  std::array<std::size_t, 256> freq{};
  for (std::size_t i = 0; i < len; ++i) ++freq[data[i]];
  double entropy = 0.0;
  const double flen = static_cast<double>(len);
  for (std::size_t b = 0; b < 256; ++b) {
    if (freq[b] == 0) continue;
    const double p = static_cast<double>(freq[b]) / flen;
    entropy -= p * std::log2(p);
  }
  return entropy;
}

/// @brief Scans a window for high-entropy blocks (potential encrypted/compressed data).
/// Emits a single evidence record if any block exceeds the threshold.
void scanEntropyBlocks(const std::vector<uint8_t>& window,
                       const uint64_t base_disk_offset,
                       const std::string& source_label,
                       const std::string& file_name,
                       std::vector<RecoveryEvidence>& results,
                       std::unordered_set<std::string>& dedup,
                       const std::size_t max_candidates,
                       const double entropy_threshold = 7.2) {
  constexpr std::size_t kBlockSize = 4096;
  for (std::size_t blk = 0;
       blk + kBlockSize <= window.size() && results.size() < max_candidates;
       blk += kBlockSize) {
    const double ent = computeShannon(window.data() + blk, kBlockSize);
    if (ent < entropy_threshold) continue;

    const uint64_t disk_off = base_disk_offset + blk;
    RecoveryEvidence ev;
    ev.executable_path = "HighEntropyBlock@" + formatOffset(disk_off);
    ev.source          = "SignatureScan";
    ev.recovered_from  = "Signature";
    std::ostringstream det;
    det << "file=" << file_name
        << " offset=" << formatOffset(disk_off)
        << " entropy=" << std::fixed << std::setprecision(2) << ent
        << " source=" << source_label;
    ev.details    = det.str();

    const std::string key = buildEvidenceDedupKey(ev);
    if (dedup.insert(key).second) results.push_back(std::move(ev));
  }
}

// ---------------------------------------------------------------------------
// File scanner
// ---------------------------------------------------------------------------

/// @brief Scans one file and appends matching evidence to @p results.
void scanFile(const fs::path& file_path,
              const std::string& source_label,
              std::size_t block_size,
              std::size_t max_bytes,
              std::size_t max_candidates,
              bool enable_entropy,
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
  std::vector<uint8_t> tail;
  tail.reserve(overlap);

  std::size_t total_read    = 0;
  uint64_t block_disk_offset = 0;
  std::size_t local_candidates = 0;

  while (total_read < max_bytes && local_candidates < max_candidates) {
    const std::size_t remaining = max_bytes - total_read;
    const std::size_t to_read   = std::min(block_size, remaining);

    file.read(reinterpret_cast<char*>(buffer.data()),
              static_cast<std::streamsize>(to_read));
    const std::size_t n = static_cast<std::size_t>(file.gcount());
    if (n == 0) break;

    // Build search window: tail of previous block + current block.
    std::vector<uint8_t> window;
    window.reserve(tail.size() + n);
    window.insert(window.end(), tail.begin(), tail.end());
    window.insert(window.end(), buffer.begin(),
                  buffer.begin() + static_cast<std::ptrdiff_t>(n));

    // Signature scan.
    for (const auto& sig : SignatureDB::kSignatures) {
      if (local_candidates >= max_candidates) break;

      const auto offsets = findSignatureOffsets(window, sig);
      for (const std::size_t artifact_start : offsets) {
        if (local_candidates >= max_candidates) break;

        const uint64_t disk_offset =
            block_disk_offset +
            (artifact_start >= tail.size() ? artifact_start - tail.size() : 0);

        if (!validateCandidate(sig, window, artifact_start + sig.file_offset)) continue;

        RecoveryEvidence ev;
        ev.executable_path = std::string(sig.artifact_type) + "@" + formatOffset(disk_offset);
        ev.source          = source_label;
        ev.recovered_from  = "Signature";
        ev.details         = "file=" + file_path.filename().string() +
                             " offset=" + formatOffset(disk_offset) +
                             " type=" + std::string(sig.artifact_type) +
                             " signature_class=" + std::string(sig.recovered_from);

        const std::string key = buildEvidenceDedupKey(ev);
        if (dedup.insert(key).second) {
          results.push_back(std::move(ev));
          ++local_candidates;
        }
      }
    }

    // Entropy scan (optional — only when configured).
    if (enable_entropy && local_candidates < max_candidates) {
      scanEntropyBlocks(window, block_disk_offset, source_label,
                        file_path.filename().string(),
                        results, dedup,
                        max_candidates - local_candidates);
      local_candidates = results.size();  // re-sync counter after entropy adds
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

    total_read       += n;
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
  if (!image_path_override.empty())
    image_path_ = std::move(image_path_override);
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

    enable_entropy_   = readBool("SignatureScanEntropy",      enable_entropy_);
    image_path_       = readStr ("SignatureScanPath",         "");
    block_size_       = static_cast<std::size_t>(
        std::max(4096, readInt("SignatureScanBlockSizeKB", 64) * 1024));
    max_scan_mb_      = static_cast<std::size_t>(
        std::max(1, readInt("SignatureScanMaxMB", static_cast<int>(max_scan_mb_))));
    max_candidates_   = static_cast<std::size_t>(
        std::max(1, readInt("SignatureScanMaxCandidates", static_cast<int>(max_candidates_))));

    for (const std::string& key :
         {"EnableSignatureScan", "SignatureScanPagefile", "SignatureScanHiberfil"}) {
      if (config.hasKey("Recovery", key)) {
        logger->warn(
            "Параметр [Recovery]/{} игнорируется: SignatureScanner всегда активен",
            key);
      }
    }
  } catch (const std::exception& e) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SignatureScanner: ошибка загрузки конфига: {}", e.what());
  }
}

std::vector<RecoveryEvidence> SignatureScanner::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  const std::size_t max_bytes = toByteLimit(max_scan_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;

  // 1. Explicit disk image
  if (!image_path_.empty()) {
    const auto resolved = findPathCaseInsensitive(fs::path(image_path_));
    if (resolved.has_value()) {
      logger->info("SignatureScan: сканирование образа \"{}\"", resolved->string());
      scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
               enable_entropy_, results, dedup);
    }
  }

  // 2. Pagefile / swapfile
  for (const auto rel : {"pagefile.sys", "swapfile.sys"}) {
    const auto resolved = findPathCaseInsensitive(fs::path(disk_root) / rel);
    if (!resolved.has_value()) continue;
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SignatureScan: сканирование pagefile \"{}\"", resolved->string());
    scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
             enable_entropy_, results, dedup);
  }

  // 3. Hibernation file
  const auto resolved =
      findPathCaseInsensitive(fs::path(disk_root) / "hiberfil.sys");
  if (resolved.has_value()) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "SignatureScan: сканирование hiberfil \"{}\"", resolved->string());
    scanFile(*resolved, "SignatureScan", block_size_, max_bytes, max_candidates_,
             enable_entropy_, results, dedup);
  }

  logger->info("Recovery(SignatureScan): total={}", results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
