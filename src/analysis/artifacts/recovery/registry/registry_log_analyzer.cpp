/// @file registry_log_analyzer.cpp
/// @brief Реализация анализатора recovery для LOG1/LOG2 и related registry logs.

#include "registry_log_analyzer.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::toLowerAscii;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::toByteLimit;

// ---------------------------------------------------------------------------
// Registry hive transaction log structures
// ---------------------------------------------------------------------------
//
// The Windows Registry transaction log (LOG1 / LOG2) consists of:
//
//   [0x000 – 0x1FF]  Base block ("regf" signature) — 512 bytes
//     +0x00  signature      "regf"
//     +0x04  primary_seq    primary sequence number
//     +0x08  secondary_seq  secondary sequence number
//     +0x0C  timestamp      8-byte FILETIME
//     +0x14  major          major format version (1)
//     +0x18  minor          minor format version
//     +0x1C  type           0 = primary hive, 1 = transaction log
//     +0x28  hive_bins_size size of all hive-bins in the primary hive
//     +0x200 checksum       XOR-based 32-bit checksum at offset 0x1FC
//
//   [0x200 – ...]  Dirty-page data (new log format, Windows 8+)
//     Each log entry begins with a magic "HvLE" (48 76 4C 45):
//       +0x00  magic          "HvLE"
//       +0x04  size           size of this log entry in bytes (incl. header)
//       +0x08  flags          bit 0 = is_complete
//       +0x0A  sequence       sequence number of this entry
//       +0x0C  hive_offset    offset in the primary hive where dirty data starts
//       +0x10  dirty_count    number of dirty 4096-byte pages in this entry
//       +0x14  hash           32-bit hash of the dirty data
//       [dirty pages follow immediately]
//
//   For the old log format (Windows Vista/7), the layout after the base
//   block is: a dirty-sector bitmap followed by raw dirty sector data.
//
// CLFS (BLF) containers have signature "CLFS BASE BLOCK\x00" at offset 0.

// ---- Low-level helpers ----

inline uint32_t readU32Le(const std::vector<uint8_t>& d, std::size_t off) {
  if (off + 4 > d.size()) return 0;
  return static_cast<uint32_t>(d[off])       |
        (static_cast<uint32_t>(d[off + 1]) << 8)  |
        (static_cast<uint32_t>(d[off + 2]) << 16) |
        (static_cast<uint32_t>(d[off + 3]) << 24);
}

inline uint64_t readU64Le(const std::vector<uint8_t>& d, std::size_t off) {
  if (off + 8 > d.size()) return 0;
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(d[off + i]) << (i * 8);
  return v;
}

// ---- Base-block validation ----

struct RegistryBaseBlock {
  bool    valid          = false;
  uint32_t primary_seq   = 0;
  uint32_t secondary_seq = 0;
  uint32_t hive_bins_sz  = 0;
  uint32_t format_minor  = 0;
  uint32_t log_type      = 0;  // 0 = primary, 1 = log
};

/// @brief Parses and validates the 512-byte base block of a registry hive/log.
RegistryBaseBlock parseBaseBlock(const std::vector<uint8_t>& data) {
  RegistryBaseBlock bb;
  if (data.size() < 512) return bb;
  // Signature "regf" = 72 65 67 66
  if (data[0] != 0x72 || data[1] != 0x65 || data[2] != 0x67 || data[3] != 0x66) return bb;

  bb.primary_seq   = readU32Le(data, 0x04);
  bb.secondary_seq = readU32Le(data, 0x08);
  bb.hive_bins_sz  = readU32Le(data, 0x28);
  bb.format_minor  = readU32Le(data, 0x18);
  bb.log_type      = readU32Le(data, 0x1C);

  // Validate checksum: XOR of the first 127 DWORDs (0x00 – 0x1F8).
  uint32_t xor_checksum = 0;
  for (std::size_t i = 0; i < 508; i += 4)
    xor_checksum ^= readU32Le(data, i);
  const uint32_t stored = readU32Le(data, 0x1FC);
  bb.valid = (xor_checksum == stored) ||
             (bb.primary_seq == bb.secondary_seq);  // Relaxed: treat consistent seq as valid.

  return bb;
}

// ---- New log format (HvLE) dirty-page extraction ----

/// @brief Extracts dirty-page blocks from the new-format transaction log.
/// @param data    Full log file content.
/// @param results Output evidence vector.
/// @param dedup   Deduplication set.
/// @param source_label  Source label for evidence.
/// @param max_candidates  Limit.
void extractHvleDirtyPages(
    const std::vector<uint8_t>& data,
    const std::string& source_label,
    std::vector<RecoveryEvidence>& results,
    std::unordered_set<std::string>& dedup,
    const std::size_t max_candidates) {
  if (data.size() < 0x220) return;

  // Log entries start after the base block (0x200).
  std::size_t pos = 0x200;
  while (pos + 0x20 <= data.size() && results.size() < max_candidates) {
    // Magic "HvLE" = 48 76 4C 45
    if (data[pos] != 0x48 || data[pos + 1] != 0x76 ||
        data[pos + 2] != 0x4C || data[pos + 3] != 0x45)
      break;

    const uint32_t entry_size   = readU32Le(data, pos + 0x04);
    const uint32_t dirty_count  = readU32Le(data, pos + 0x10);
    const uint32_t hive_offset  = readU32Le(data, pos + 0x0C);

    if (entry_size < 0x20 || pos + entry_size > data.size()) break;

    // Dirty pages start immediately after the 0x20-byte header.
    const std::size_t pages_start = pos + 0x20;
    constexpr std::size_t kPageSize = 4096;

    for (uint32_t pg = 0;
         pg < dirty_count && results.size() < max_candidates;
         ++pg) {
      const std::size_t pg_off = pages_start + pg * kPageSize;
      if (pg_off + kPageSize > data.size()) break;

      const std::vector<uint8_t> page_data(
          data.begin() + static_cast<std::ptrdiff_t>(pg_off),
          data.begin() + static_cast<std::ptrdiff_t>(pg_off + kPageSize));

      // Scan the page for executable paths.
      const auto candidates = EvidenceUtils::extractExecutableCandidatesFromBinary(
          page_data, max_candidates - results.size());
      for (const auto& exe : candidates) {
        if (results.size() >= max_candidates) break;
        RecoveryEvidence e;
        e.executable_path = exe;
        e.source          = "Registry";
        e.recovered_from  = source_label + "(HvLE_dirty_page)";
        std::ostringstream det;
        det << "hive_offset=0x" << std::hex << (hive_offset + pg * kPageSize)
            << " page=" << std::dec << pg;
        e.details    = det.str();
        const std::string key = e.executable_path + "|" + e.recovered_from + "|" + e.details;
        if (dedup.insert(key).second)
          results.push_back(std::move(e));
      }
    }

    pos += (entry_size + 511) & ~511u;  // entries are aligned to 512 bytes
  }
}

// ---- Old log format (Vista/7) dirty-sector extraction ----

/// @brief Extracts dirty sectors from the Vista/Windows7 log format.
///
/// Format after base block:
///   [0x200] bitmap   (ceil(hive_bins_sz / 512 / 8) bytes rounded to 512)
///   [after bitmap]   raw dirty sectors in order of bits set in bitmap
void extractOldFormatDirtySectors(
    const std::vector<uint8_t>& data,
    const uint32_t hive_bins_sz,
    const std::string& source_label,
    std::vector<RecoveryEvidence>& results,
    std::unordered_set<std::string>& dedup,
    const std::size_t max_candidates) {
  if (data.size() < 0x400 || hive_bins_sz == 0) return;

  constexpr std::size_t kSectorSize = 512;
  const std::size_t sector_count = (hive_bins_sz + kSectorSize - 1) / kSectorSize;
  const std::size_t bitmap_bytes = (sector_count + 7) / 8;
  const std::size_t bitmap_aligned = (bitmap_bytes + kSectorSize - 1) & ~(kSectorSize - 1);
  const std::size_t dirty_start = 0x200 + bitmap_aligned;

  if (dirty_start >= data.size()) return;

  std::size_t dirty_pos = dirty_start;
  for (std::size_t byte_idx = 0;
       byte_idx < bitmap_bytes && dirty_pos + kSectorSize <= data.size() &&
       results.size() < max_candidates;
       ++byte_idx) {
    const uint8_t bitmap_byte = data[0x200 + byte_idx];
    for (int bit = 0; bit < 8; ++bit) {
      if (!(bitmap_byte & (1 << bit))) continue;
      if (dirty_pos + kSectorSize > data.size()) break;
      if (results.size() >= max_candidates) break;

      const std::vector<uint8_t> sector(
          data.begin() + static_cast<std::ptrdiff_t>(dirty_pos),
          data.begin() + static_cast<std::ptrdiff_t>(dirty_pos + kSectorSize));

      const auto candidates = EvidenceUtils::extractExecutableCandidatesFromBinary(
          sector, max_candidates - results.size());
      for (const auto& exe : candidates) {
        if (results.size() >= max_candidates) break;
        RecoveryEvidence e;
        e.executable_path = exe;
        e.source          = "Registry";
        e.recovered_from  = source_label + "(dirty_sector)";
        std::ostringstream det;
        det << "sector=" << (byte_idx * 8 + bit)
            << " hive_offset=0x" << std::hex << ((byte_idx * 8 + bit) * kSectorSize);
        e.details    = det.str();
        const std::string key = e.executable_path + "|" + e.recovered_from + "|" + e.details;
        if (dedup.insert(key).second)
          results.push_back(std::move(e));
      }

      dirty_pos += kSectorSize;
    }
  }
}

// ---- CLFS (BLF) container scan ----

/// @brief Checks for a CLFS base-block signature and scans record data.
bool isCLFSContainer(const std::vector<uint8_t>& data) {
  // "CLFS BASE BLOCK\0" = 43 4C 46 53 20 42 41 53 45 20 42 4C 4F 43 4B 00
  static const uint8_t kClfsBase[16] = {
      0x43,0x4C,0x46,0x53,0x20,0x42,0x41,0x53,
      0x45,0x20,0x42,0x4C,0x4F,0x43,0x4B,0x00};
  return data.size() >= 16 &&
         std::memcmp(data.data(), kClfsBase, 16) == 0;
}

// ---- File type classifier ----

bool isRegistryTransactionLogFile(const fs::path& path) {
  const std::string name_lower = toLowerAscii(path.filename().string());
  if (name_lower.ends_with(".log1"))        return true;
  if (name_lower.ends_with(".log2"))        return true;
  if (name_lower.ends_with(".blf"))         return true;
  if (name_lower.ends_with(".regtrans-ms")) return true;
  return false;
}

/// @brief Parses one transaction-log file and appends evidence.
void processLogFile(
    const fs::path& log_path,
    std::vector<RecoveryEvidence>& results,
    std::unordered_set<std::string>& dedup,
    const std::size_t max_bytes,
    const std::size_t max_candidates) {
  const auto data_opt = readFilePrefix(log_path, max_bytes);
  if (!data_opt.has_value() || data_opt->empty()) return;
  const auto& data = *data_opt;

  const std::string source_label = "RegistryLog(" + log_path.filename().string() + ")";

  // ---- CLFS / BLF container ----
  if (isCLFSContainer(data)) {
    // CLFS records start at offset 0x200 after the base block header.
    // We do a generic binary scan of the entire container for exec paths.
    const auto candidates = EvidenceUtils::extractExecutableCandidatesFromBinary(
        data, max_candidates - results.size());
    for (const auto& exe : candidates) {
      if (results.size() >= max_candidates) break;
      RecoveryEvidence e;
      e.executable_path = exe;
      e.source          = "Registry";
      e.recovered_from  = "RegistryLog(BLF)";
      e.details         = "blf=" + log_path.filename().string();
      const std::string key = e.executable_path + "|" + e.recovered_from;
      if (dedup.insert(key).second) results.push_back(std::move(e));
    }
    return;
  }

  // ---- Registry log (regf base block) ----
  const auto bb = parseBaseBlock(data);
  if (bb.valid) {
    // Check for new HvLE format (Windows 8+): look for "HvLE" magic at 0x200.
    bool is_hvle = (data.size() > 0x204 &&
                    data[0x200] == 0x48 && data[0x201] == 0x76 &&
                    data[0x202] == 0x4C && data[0x203] == 0x45);

    if (is_hvle) {
      extractHvleDirtyPages(data, source_label, results, dedup, max_candidates);
    } else {
      extractOldFormatDirtySectors(data, bb.hive_bins_sz, source_label,
                                    results, dedup, max_candidates);
    }
  }

  // ---- Fallback binary scan (always, catches anything missed above) ----
  const auto bin_candidates = EvidenceUtils::extractExecutableCandidatesFromBinary(
      data, max_candidates > results.size() ? max_candidates - results.size() : 0);
  for (const auto& exe : bin_candidates) {
    if (results.size() >= max_candidates) break;
    RecoveryEvidence e;
    e.executable_path = exe;
    e.source          = "Registry";
    e.recovered_from  = "RegistryLog(binary)";
    e.details         = "file=" + log_path.filename().string();
    const std::string key = e.executable_path + "|RegistryLog(binary)";
    if (dedup.insert(key).second) results.push_back(std::move(e));
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// RegistryLogAnalyzer — public API
// ---------------------------------------------------------------------------

RegistryLogAnalyzer::RegistryLogAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void RegistryLogAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));
      registry_config_path_ = config.getString("Recovery", "RegistryConfigPath",
                                               registry_config_path_);

      if (config.hasKey("Recovery", "EnableRegistryLogsRecovery")) {
        logger->warn("Параметр [Recovery]/EnableRegistryLogsRecovery игнорируется: "
                     "модуль Registry всегда активен");
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки RegistryLogAnalyzer");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Ошибка чтения [Recovery] для RegistryLogs: {}", e.what());
  }
}

std::vector<RecoveryEvidence> RegistryLogAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  const fs::path registry_root = fs::path(disk_root) / registry_config_path_;
  const auto resolved_registry_root = findPathCaseInsensitive(registry_root);
  if (!resolved_registry_root.has_value()) {
    logger->info("Recovery(RegistryLogs LOG1/LOG2): binary=0 total=0");
    return {};
  }

  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::size_t file_count = 0;

  std::error_code ec;
  for (const auto& entry : fs::recursive_directory_iterator(
           *resolved_registry_root,
           fs::directory_options::skip_permission_denied, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    if (!isRegistryTransactionLogFile(entry.path())) continue;

    ++file_count;
    processLogFile(entry.path(), results, dedup, max_bytes, max_candidates_per_source_);
    if (results.size() >= max_candidates_per_source_) break;
  }

  logger->info("Recovery(RegistryLogs LOG1/LOG2): files={} total={}",
               file_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
