/// @file ntfs_metadata_analyzer.cpp
/// @brief Реализация recovery-анализатора NTFS-метаданных.

#include "ntfs_metadata_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <sstream>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBFSNTFS) && PROGRAM_TRACES_HAVE_LIBFSNTFS
#include <libfsntfs.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryBufferBinary;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

/// @brief Читает LE `uint16_t` из буфера.
/// @param bytes Буфер байтов.
/// @param offset Смещение.
/// @return Значение или `0`, если смещение невалидно.
uint16_t readLeUInt16(const std::vector<uint8_t>& bytes,
                      const std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;
  return static_cast<uint16_t>(
      static_cast<uint16_t>(bytes[offset]) |
      static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

/// @brief Форматирует смещение в hex.
/// @param offset Смещение.
/// @return Строка вида `0x...`.
std::string formatOffsetHex(const std::size_t offset) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::uppercase << offset;
  return stream.str();
}

/// @brief Fallback-парсинг `$MFT` с учетом FILE-record.
/// @param mft_path Путь к `$MFT`.
/// @param max_bytes Лимит читаемых байтов.
/// @param max_candidates Лимит кандидатов.
/// @param record_size Размер записи MFT.
/// @param max_records Лимит записей.
/// @return Recovery evidence, полученные из `$MFT`.
std::vector<RecoveryEvidence> parseMftFallback(
    const fs::path& mft_path, const std::size_t max_bytes,
    const std::size_t max_candidates, const std::size_t record_size,
    const std::size_t max_records) {
  std::vector<RecoveryEvidence> results;
  if (record_size < 256 || max_candidates == 0) return results;

  const auto data_opt = readFilePrefix(mft_path, max_bytes);
  if (!data_opt.has_value() || data_opt->empty()) return results;

  std::error_code ec;
  const std::string timestamp =
      EvidenceUtils::fileTimeToUtcString(fs::last_write_time(mft_path, ec));

  std::unordered_set<std::string> dedup;
  std::size_t parsed_records = 0;
  const std::vector<uint8_t>& data = *data_opt;

  for (std::size_t offset = 0;
       offset + record_size <= data.size() && parsed_records < max_records &&
       results.size() < max_candidates;
       offset += record_size) {
    if (!(data[offset] == 'F' && data[offset + 1] == 'I' &&
          data[offset + 2] == 'L' && data[offset + 3] == 'E')) {
      continue;
    }

    parsed_records++;

    const uint16_t flags = readLeUInt16(data, offset + 0x16);
    const bool in_use = (flags & 0x0001) != 0;
    const bool directory = (flags & 0x0002) != 0;

    std::vector<uint8_t> record_buffer;
    record_buffer.reserve(record_size);
    const auto record_begin_it =
        data.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto record_end_it =
        data.begin() +
        static_cast<std::ptrdiff_t>(offset + record_size);
    record_buffer.insert(record_buffer.end(), record_begin_it, record_end_it);

    auto record_evidence = scanRecoveryBufferBinary(
        record_buffer, "NTFSMetadata", "$MFT(binary)", mft_path.filename().string(),
        timestamp, max_candidates - results.size(), offset, "mft_record",
        data.size());

    for (auto& evidence : record_evidence) {
      std::ostringstream details;
      if (!evidence.details.empty()) {
        details << evidence.details << ", ";
      }
      details << "record_offset=" << formatOffsetHex(offset) << ", flags="
              << (in_use ? "in_use" : "deleted");
      if (directory) {
        details << "|directory";
      }
      evidence.details = details.str();
      if (!in_use) {
        evidence.tamper_flag = "ntfs_deleted_record_execution_candidate";
      }
    }

    appendUniqueEvidence(results, record_evidence, dedup);
  }

  return results;
}

}  // namespace

NTFSMetadataAnalyzer::NTFSMetadataAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void NTFSMetadataAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      enabled_ =
          config.getBool("Recovery", "EnableNTFSMetadata", enabled_);
      enable_native_fsntfs_parser_ = config.getBool(
          "Recovery", "EnableNativeFsntfsParser", enable_native_fsntfs_parser_);
      fsntfs_fallback_to_binary_on_native_failure_ =
          config.getBool("Recovery", "FsntfsFallbackToBinaryOnNativeFailure",
                         fsntfs_fallback_to_binary_on_native_failure_);
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));
      mft_record_size_ = static_cast<std::size_t>(std::max(
          256, config.getInt("Recovery", "MFTRecordSize",
                             static_cast<int>(mft_record_size_))));
      mft_max_records_ = static_cast<std::size_t>(std::max(
          1000, config.getInt("Recovery", "MFTMaxRecords",
                              static_cast<int>(mft_max_records_))));
      mft_path_ = config.getString("Recovery", "MFTPath", mft_path_);
      bitmap_path_ = config.getString("Recovery", "BitmapPath", bitmap_path_);
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки NTFSMetadataAnalyzer");
    logger->debug("Ошибка чтения [Recovery] для NTFSMetadata: {}", e.what());
  }
}

std::vector<RecoveryEvidence> NTFSMetadataAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->debug("NTFSMetadata-анализ отключен в конфигурации");
    return {};
  }

  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::size_t native_count = 0;
  std::size_t binary_count = 0;

  const fs::path mft_candidate = fs::path(disk_root) / mft_path_;
  if (const auto resolved_mft = findPathCaseInsensitive(mft_candidate);
      resolved_mft.has_value()) {
    bool need_binary_fallback = true;
    if (enable_native_fsntfs_parser_) {
#if defined(PROGRAM_TRACES_HAVE_LIBFSNTFS) && PROGRAM_TRACES_HAVE_LIBFSNTFS
      logger->debug("NTFSMetadata(native): libfsntfs подключен, но native "
                    "парсер пока experimental и использует fallback");
      need_binary_fallback = fsntfs_fallback_to_binary_on_native_failure_;
#else
      logger->debug("NTFSMetadata(native): libfsntfs недоступен в текущей сборке");
      need_binary_fallback = true;
#endif
    }

    if (!enable_native_fsntfs_parser_ || need_binary_fallback) {
      auto mft_evidence =
          parseMftFallback(*resolved_mft, max_bytes, max_candidates_per_source_,
                           mft_record_size_, mft_max_records_);
      binary_count += mft_evidence.size();
      appendUniqueEvidence(results, mft_evidence, dedup);
    } else {
      native_count++;
    }
  }

  const fs::path bitmap_candidate = fs::path(disk_root) / bitmap_path_;
  if (const auto resolved_bitmap = findPathCaseInsensitive(bitmap_candidate);
      resolved_bitmap.has_value()) {
    auto bitmap_evidence = scanRecoveryFileBinary(
        *resolved_bitmap, "NTFSMetadata", "$Bitmap(binary)", max_bytes,
        max_candidates_per_source_);
    binary_count += bitmap_evidence.size();
    appendUniqueEvidence(results, bitmap_evidence, dedup);
  }

  logger->info("Recovery(NTFSMetadata $MFT/$Bitmap): native={} binary={} total={}",
               native_count, binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
