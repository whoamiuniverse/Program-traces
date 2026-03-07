/// @file hibernation_analyzer.cpp
/// @brief Реализация анализатора `hiberfil.sys`.

#include "hibernation_analyzer.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
#include <libhibr.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryBufferBinary;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

struct NativeHiberParseResult {
  bool attempted = false;
  bool success = false;
  std::vector<RecoveryEvidence> evidence;
};

#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
/// @brief Преобразует объект ошибки libhibr в строку.
/// @param error Указатель на ошибку.
/// @return Человекочитаемое сообщение.
std::string toLibhibrErrorMessage(libhibr_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libhibr";

  std::array<char, 2048> buffer{};
  if (libhibr_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить описание ошибки libhibr";
}

/// @brief Выполняет native-скан `hiberfil.sys` через libhibr.
/// @param hiber_path Путь к hiberfil.
/// @param max_pages Максимум читаемых страниц (4KB/page).
/// @param max_bytes Глобальный byte-limit для сканирования.
/// @param max_candidates Лимит извлеченных кандидатов.
/// @return Результат native-парсинга.
NativeHiberParseResult parseHiberNative(const fs::path& hiber_path,
                                        const std::size_t max_pages,
                                        const std::size_t max_bytes,
                                        const std::size_t max_candidates) {
  NativeHiberParseResult result;
  result.attempted = true;

  const auto logger = GlobalLogger::get();
  libhibr_error_t* error = nullptr;
  if (libhibr_check_file_signature(hiber_path.string().c_str(), &error) != 1) {
    logger->debug("Hiber(native): сигнатура не распознана для \"{}\": {}",
                  hiber_path.string(), toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    return result;
  }
  libhibr_error_free(&error);

  libhibr_file_t* file = nullptr;
  if (libhibr_file_initialize(&file, &error) != 1 || file == nullptr) {
    logger->debug("Hiber(native): инициализация не удалась: {}",
                  toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    return result;
  }
  libhibr_error_free(&error);

  auto close_and_free = [&]() {
    if (file == nullptr) return;
    libhibr_error_t* close_error = nullptr;
    if (libhibr_file_close(file, &close_error) != 0) {
      logger->debug("Hiber(native): close завершился с ошибкой: {}",
                    toLibhibrErrorMessage(close_error));
    }
    libhibr_error_free(&close_error);

    libhibr_error_t* free_error = nullptr;
    if (libhibr_file_free(&file, &free_error) != 1) {
      logger->debug("Hiber(native): free завершился с ошибкой: {}",
                    toLibhibrErrorMessage(free_error));
    }
    libhibr_error_free(&free_error);
  };

  const int access_flags = libhibr_get_access_flags_read();
  error = nullptr;
  if (libhibr_file_open(file, hiber_path.string().c_str(), access_flags, &error) !=
      1) {
    logger->debug("Hiber(native): не удалось открыть \"{}\": {}",
                  hiber_path.string(), toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    close_and_free();
    return result;
  }
  libhibr_error_free(&error);
  result.success = true;

  size64_t media_size = 0;
  if (libhibr_file_get_media_size(file, &media_size, &error) != 1) {
    logger->debug("Hiber(native): не удалось определить размер: {}",
                  toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    close_and_free();
    return result;
  }
  libhibr_error_free(&error);

  constexpr std::size_t kPageSize = 4096;
  constexpr std::size_t kChunkPages = 16;
  const std::size_t chunk_size = kPageSize * kChunkPages;
  const std::size_t page_limited_bytes = max_pages * kPageSize;
  const std::size_t scan_limit = std::min<std::size_t>(
      max_bytes, std::min<std::size_t>(page_limited_bytes, media_size));

  std::vector<uint8_t> chunk(chunk_size);
  std::unordered_set<std::string> dedup;
  std::error_code ec;
  const std::string timestamp =
      EvidenceUtils::fileTimeToUtcString(fs::last_write_time(hiber_path, ec));

  for (std::size_t offset = 0;
       offset < scan_limit && result.evidence.size() < max_candidates;
       offset += chunk_size) {
    const std::size_t to_read = std::min(chunk_size, scan_limit - offset);
    error = nullptr;
    const ssize_t read_size = libhibr_file_read_buffer_at_offset(
        file, chunk.data(), to_read, static_cast<off64_t>(offset), &error);
    if (read_size < 0) {
      logger->debug("Hiber(native): ошибка чтения offset={}: {}", offset,
                    toLibhibrErrorMessage(error));
      libhibr_error_free(&error);
      break;
    }
    libhibr_error_free(&error);
    if (read_size == 0) break;

    std::vector<uint8_t> scan_buffer(
        chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(read_size));
    auto scan_result = scanRecoveryBufferBinary(
        scan_buffer, "Memory", "Hiber(native)", hiber_path.filename().string(),
        timestamp, max_candidates - result.evidence.size(), offset,
        "hiber_native_chunk", scan_limit);
    appendUniqueEvidence(result.evidence, scan_result, dedup);
  }

  close_and_free();
  return result;
}
#endif

}  // namespace

HibernationAnalyzer::HibernationAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void HibernationAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();

  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      enabled_ = config.getBool("Recovery", "EnableHiber", enabled_);
      enable_native_hiber_parser_ = config.getBool(
          "Recovery", "EnableNativeHiberParser", enable_native_hiber_parser_);
      hiber_fallback_to_binary_ = config.getBool(
          "Recovery", "HiberFallbackToBinary", hiber_fallback_to_binary_);
      hiber_max_pages_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "HiberMaxPages",
                           static_cast<int>(hiber_max_pages_))));
      hiber_path_ = config.getString("Recovery", "HiberPath", hiber_path_);
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки HibernationAnalyzer");
    logger->debug("Ошибка чтения [Recovery] для Hiber: {}", e.what());
  }
}

std::vector<RecoveryEvidence> HibernationAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();
  if (!enabled_) {
    logger->debug("Hibernation-анализ отключен в конфигурации");
    return {};
  }

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  std::size_t native_count = 0;
  std::size_t binary_count = 0;

  std::vector<fs::path> candidates;
  if (!hiber_path_.empty()) {
    const fs::path configured(hiber_path_);
    if (configured.is_absolute()) {
      candidates.push_back(configured);
    } else {
      candidates.push_back(fs::path(disk_root) / configured);
    }
  }
  candidates.push_back(fs::path(disk_root) / "hiberfil.sys");

  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()),
                   candidates.end());

  for (const fs::path& candidate : candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    bool need_binary_fallback = true;
    if (enable_native_hiber_parser_) {
#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
      logger->debug("Hiber(native): включен experimental режим libhibr");
      NativeHiberParseResult native_result =
          parseHiberNative(*resolved, hiber_max_pages_, max_bytes,
                           max_candidates_per_source_);
      native_count += native_result.evidence.size();
      need_binary_fallback =
          hiber_fallback_to_binary_ &&
          (!native_result.success || native_result.evidence.empty());
      appendUniqueEvidence(results, native_result.evidence, dedup);
#else
      logger->debug("Hiber(native): libhibr недоступен в текущей сборке");
      need_binary_fallback = true;
#endif
    }

    if (!enable_native_hiber_parser_ || need_binary_fallback) {
      auto fallback = scanRecoveryFileBinary(*resolved, "Memory", "Hiber(binary)",
                                             max_bytes, max_candidates_per_source_);
      binary_count += fallback.size();
      appendUniqueEvidence(results, fallback, dedup);
    }
  }

  logger->info("Recovery(Hiber): native={} binary={} total={}", native_count,
               binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
