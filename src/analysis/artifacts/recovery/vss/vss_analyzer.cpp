/// @file vss_analyzer.cpp
/// @brief Реализация анализатора восстановления VSS/Pagefile/Memory.

#include "vss_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBVSHADOW) && PROGRAM_TRACES_HAVE_LIBVSHADOW
#include <libvshadow.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::toLowerAscii;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

constexpr std::size_t kVssStreamChunkSize = 512 * 1024;
constexpr std::size_t kVssStreamTailSize = 4096;
constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

struct NativeVssParseResult {
  bool attempted = false;
  bool success = false;
  bool partial_corruption_detected = false;
  std::size_t stores_processed = 0;
  std::size_t stores_failed = 0;
  std::vector<RecoveryEvidence> evidence;
};

void appendVssLimits(std::vector<RecoveryEvidence>& evidence,
                     std::size_t max_bytes,
                     std::size_t max_candidates);

/// @brief Ищет snapshot-root директории в `System Volume Information`.
/// @param svi_root Корень `System Volume Information`.
/// @return Список найденных директорий snapshot.
std::vector<fs::path> findSnapshotRoots(const fs::path& svi_root) {
  std::vector<fs::path> roots;
  std::unordered_set<std::string> dedup;
  std::error_code ec;

  for (const auto& entry :
       fs::recursive_directory_iterator(
           svi_root, fs::directory_options::skip_permission_denied, ec)) {
    if (ec) break;
    if (!entry.is_directory()) continue;

    const std::string name_lower =
        toLowerAscii(entry.path().filename().string());
    if (name_lower.find("harddiskvolumeshadowcopy") == std::string::npos) {
      continue;
    }

    const std::string root = entry.path().string();
    if (!dedup.insert(root).second) continue;
    roots.push_back(entry.path());
  }
  std::sort(roots.begin(), roots.end());
  return roots;
}

/// @brief Выполняет replay ключевых артефактов по найденным snapshot-root.
/// @param disk_root Корневой путь диска.
/// @param max_bytes Лимит чтения bytes.
/// @param max_candidates Лимит кандидатов.
/// @param max_files Лимит обрабатываемых snapshot-файлов.
/// @return Набор evidence из snapshot replay.
std::vector<RecoveryEvidence> collectSnapshotReplayEvidence(
    const std::string& disk_root, const std::size_t max_bytes,
    const std::size_t max_candidates, const std::size_t max_files) {
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  std::size_t processed_files = 0;

  const fs::path svi_dir = fs::path(disk_root) / "System Volume Information";
  const auto resolved_svi = findPathCaseInsensitive(svi_dir);
  if (!resolved_svi.has_value()) return results;

  const auto snapshot_roots = findSnapshotRoots(*resolved_svi);
  for (const fs::path& snapshot_root : snapshot_roots) {
    if (processed_files >= max_files) break;

    const std::vector<std::pair<fs::path, std::string_view>> replay_targets = {
        {snapshot_root / "Windows" / "appcompat" / "Programs" / "Amcache.hve",
         "amcache_hive"},
        {snapshot_root / "Windows" / "System32" / "winevt" / "Logs" /
             "Security.evtx",
         "security_evtx"},
        {snapshot_root / "Windows" / "System32" / "Tasks", "scheduled_tasks"},
        {snapshot_root / "Windows" / "System32" / "config" / "SYSTEM",
         "system_hive"},
        {snapshot_root / "Users" / "Default" / "NTUSER.DAT",
         "ntuser_hive"},
    };

    for (const auto& [path, replay_target] : replay_targets) {
      if (processed_files >= max_files) break;
      const auto resolved = findPathCaseInsensitive(path);
      if (!resolved.has_value()) continue;
      if (!fs::is_regular_file(*resolved)) continue;

      auto evidence = scanRecoveryFileBinary(
          *resolved, "VSS", "VSS.snapshot_replay", max_bytes,
          max_candidates);
      appendVssLimits(evidence, max_bytes, max_candidates);
      for (auto& item : evidence) {
        item.details += ", snapshot_root=" + snapshot_root.string();
        item.details += ", replay_target=" + std::string(replay_target);
      }
      appendUniqueEvidence(results, evidence, dedup);
      processed_files++;
    }

    const fs::path prefetch_dir = snapshot_root / "Windows" / "Prefetch";
    const auto resolved_prefetch = findPathCaseInsensitive(prefetch_dir);
    if (!resolved_prefetch.has_value()) continue;
    std::error_code ec;
    if (!fs::exists(*resolved_prefetch, ec) || ec ||
        !fs::is_directory(*resolved_prefetch, ec)) {
      continue;
    }

    std::vector<fs::path> prefetch_files;
    for (const auto& entry :
         fs::directory_iterator(*resolved_prefetch,
                                fs::directory_options::skip_permission_denied, ec)) {
      if (processed_files >= max_files || ec) break;
      if (!entry.is_regular_file()) continue;
      if (toLowerAscii(entry.path().extension().string()) != ".pf") continue;
      prefetch_files.push_back(entry.path());
    }
    std::sort(prefetch_files.begin(), prefetch_files.end());

    for (const auto& prefetch_file : prefetch_files) {
      if (processed_files >= max_files) break;
      auto evidence = scanRecoveryFileBinary(prefetch_file, "VSS",
                                             "VSS.snapshot_prefetch",
                                             max_bytes, max_candidates);
      appendVssLimits(evidence, max_bytes, max_candidates);
      for (auto& item : evidence) {
        item.details += ", snapshot_root=" + snapshot_root.string();
        item.details += ", replay_target=prefetch";
      }
      appendUniqueEvidence(results, evidence, dedup);
      processed_files++;
    }
  }

  return results;
}

/// @brief Форматирует валидный FILETIME в UTC-строку.
/// @param filetime FILETIME.
/// @return Время в формате `YYYY-MM-DD HH:MM:SS` либо пустая строка.
std::string formatReasonableFiletime(const uint64_t filetime) {
  if (filetime < kFiletimeUnixEpoch || filetime > kMaxReasonableFiletime) {
    return {};
  }

  const std::string timestamp = filetimeToString(filetime);
  if (timestamp == "N/A") return {};
  return timestamp;
}

/// @brief Возвращает приоритет recovered_from для разрешения дублей.
/// @param recovered_from Канонический marker источника восстановления.
/// @return Приоритет: больше — лучше.
int vssRecoveredFromPriority(std::string recovered_from) {
  recovered_from = toLowerAscii(std::move(recovered_from));
  if (recovered_from.find("vss.native") != std::string::npos) return 5;
  if (recovered_from.find("snapshot_replay") != std::string::npos) return 4;
  if (recovered_from.find("snapshot_prefetch") != std::string::npos) return 3;
  if (recovered_from.find("pagefile") != std::string::npos) return 2;
  if (recovered_from.find("memory_dump") != std::string::npos) return 2;
  if (recovered_from.find("unallocated") != std::string::npos) return 2;
  if (recovered_from.find("vss.binary") != std::string::npos) return 1;
  return 0;
}

/// @brief Удаляет дубликаты кандидатов между native/snapshot/binary ветками.
/// @param evidence Набор VSS-кандидатов.
void deduplicateVssEvidence(std::vector<RecoveryEvidence>& evidence) {
  if (evidence.size() < 2) return;

  std::unordered_map<std::string, std::size_t> best_index_by_key;
  std::vector<RecoveryEvidence> deduped;
  deduped.reserve(evidence.size());

  for (auto& item : evidence) {
    std::string path = item.executable_path;
    trim(path);
    if (path.empty()) continue;

    // Include recovered_from in the dedup key so that evidence from different
    // VSS snapshots (which carry different recovered_from markers) is preserved.
    // Without this, timeline information from distinct snapshots is lost.
    const std::string key = toLowerAscii(path) + "|" + toLowerAscii(item.source) +
                            "|" + toLowerAscii(item.recovered_from);
    const int candidate_priority =
        vssRecoveredFromPriority(item.recovered_from);

    const auto it = best_index_by_key.find(key);
    if (it == best_index_by_key.end()) {
      best_index_by_key.emplace(key, deduped.size());
      deduped.push_back(std::move(item));
      continue;
    }

    auto& current = deduped[it->second];
    const int current_priority = vssRecoveredFromPriority(current.recovered_from);
    const bool replace = candidate_priority > current_priority ||
                         (candidate_priority == current_priority &&
                          !item.timestamp.empty() && current.timestamp.empty());
    if (replace) {
      current = std::move(item);
    }
  }

  evidence = std::move(deduped);
}

/// @brief Добавляет scan limits к деталям evidence.
/// @param evidence Набор evidence для аннотации.
/// @param max_bytes Лимит чтения в байтах.
/// @param max_candidates Лимит кандидатов.
void appendVssLimits(std::vector<RecoveryEvidence>& evidence,
                     const std::size_t max_bytes,
                     const std::size_t max_candidates) {
  for (auto& item : evidence) {
    std::ostringstream details;
    if (!item.details.empty()) {
      details << item.details << ", ";
    }
    details << "limit_bytes=" << max_bytes
            << ", limit_candidates=" << max_candidates;
    item.details = details.str();
  }
}

#if defined(PROGRAM_TRACES_HAVE_LIBVSHADOW) && PROGRAM_TRACES_HAVE_LIBVSHADOW
/// @brief Конвертирует ошибку libvshadow в строку.
/// @param error Указатель на объект ошибки.
/// @return Диагностическое сообщение.
std::string toLibvshadowErrorMessage(libvshadow_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libvshadow";

  std::array<char, 2048> buffer{};
  if (libvshadow_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libvshadow";
}

/// @brief Сканирует snapshot store по чанкам и извлекает кандидаты.
/// @param store Указатель на `libvshadow_store_t`.
/// @param max_bytes Максимум читаемых байтов.
/// @param max_candidates Лимит кандидатов.
/// @return Дедуплицированный список путей кандидатов.
std::vector<std::string> collectCandidatesFromVssStore(
    libvshadow_store_t* store, const std::size_t max_bytes,
    const std::size_t max_candidates) {
  std::vector<std::string> result;
  if (store == nullptr || max_candidates == 0 || max_bytes == 0) return result;

  std::unordered_set<std::string> seen;
  std::vector<uint8_t> tail;
  std::vector<uint8_t> chunk(std::min(kVssStreamChunkSize, max_bytes));

  std::size_t total_read = 0;
  while (total_read < max_bytes && result.size() < max_candidates) {
    const std::size_t remaining = max_bytes - total_read;
    const std::size_t to_read = std::min(chunk.size(), remaining);

    libvshadow_error_t* error = nullptr;
    const ssize_t read_size =
        libvshadow_store_read_buffer(store, chunk.data(), to_read, &error);
    if (read_size <= 0) {
      libvshadow_error_free(&error);
      break;
    }
    libvshadow_error_free(&error);

    std::vector<uint8_t> scan_data;
    scan_data.reserve(tail.size() + static_cast<std::size_t>(read_size));
    scan_data.insert(scan_data.end(), tail.begin(), tail.end());
    const auto read_end =
        chunk.begin() + static_cast<std::ptrdiff_t>(read_size);
    scan_data.insert(scan_data.end(), chunk.begin(), read_end);

    const auto candidates = extractExecutableCandidatesFromBinary(
        scan_data, max_candidates * 2);
    for (const std::string& candidate : candidates) {
      const std::string lowered = toLowerAscii(candidate);
      if (!seen.insert(lowered).second) continue;
      result.push_back(candidate);
      if (result.size() >= max_candidates) break;
    }

    const std::size_t tail_size = std::min(scan_data.size(), kVssStreamTailSize);
    tail.assign(scan_data.end() - static_cast<std::ptrdiff_t>(tail_size),
                scan_data.end());

    total_read += static_cast<std::size_t>(read_size);
  }

  return result;
}

/// @brief Нативно парсит VSS-volume через libvshadow.
/// @param volume_path Путь к raw/device источнику.
/// @param max_bytes Лимит чтения данных store.
/// @param max_candidates Лимит кандидатов для результата.
/// @param max_stores Лимит числа snapshot stores.
/// @return Результат native-парсинга.
NativeVssParseResult parseVssVolumeNative(const fs::path& volume_path,
                                          const std::size_t max_bytes,
                                          const std::size_t max_candidates,
                                          const std::size_t max_stores) {
  NativeVssParseResult result;
  result.attempted = true;

  const auto logger = GlobalLogger::get();
  libvshadow_volume_t* volume = nullptr;
  libvshadow_error_t* error = nullptr;

  if (libvshadow_volume_initialize(&volume, &error) != 1 || volume == nullptr) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): инициализация libvshadow не удалась: {}",
                  toLibvshadowErrorMessage(error));
    libvshadow_error_free(&error);
    return result;
  }
  libvshadow_error_free(&error);

  auto free_volume = [&]() {
    if (volume == nullptr) return;

    libvshadow_error_t* close_error = nullptr;
    if (libvshadow_volume_close(volume, &close_error) != 0) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): close volume завершился с ошибкой: {}",
                    toLibvshadowErrorMessage(close_error));
    }
    libvshadow_error_free(&close_error);

    libvshadow_error_t* free_error = nullptr;
    if (libvshadow_volume_free(&volume, &free_error) != 1) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): free volume завершился с ошибкой: {}",
                    toLibvshadowErrorMessage(free_error));
    }
    libvshadow_error_free(&free_error);
  };

  const int access_flags = libvshadow_get_access_flags_read();
  error = nullptr;
  if (libvshadow_volume_open(volume, volume_path.string().c_str(), access_flags,
                             &error) != 1) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): не удалось открыть \"{}\": {}",
                  volume_path.string(), toLibvshadowErrorMessage(error));
    libvshadow_error_free(&error);
    free_volume();
    return result;
  }
  libvshadow_error_free(&error);
  result.success = true;

  int store_count = 0;
  error = nullptr;
  if (libvshadow_volume_get_number_of_stores(volume, &store_count, &error) != 1 ||
      store_count <= 0) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): stores недоступны для \"{}\": {}",
                  volume_path.string(), toLibvshadowErrorMessage(error));
    result.partial_corruption_detected = true;
    result.stores_failed++;
    libvshadow_error_free(&error);
    free_volume();
    return result;
  }
  libvshadow_error_free(&error);

  const int limit = static_cast<int>(std::min<std::size_t>(
      max_stores, static_cast<std::size_t>(store_count)));

  std::unordered_set<std::string> dedup;
  for (int store_index = 0; store_index < limit; ++store_index) {
    libvshadow_store_t* store = nullptr;
    error = nullptr;
    if (libvshadow_volume_get_store(volume, store_index, &store, &error) != 1 ||
        store == nullptr) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): не удалось получить store #{}: {}",
                    store_index, toLibvshadowErrorMessage(error));
      result.partial_corruption_detected = true;
      result.stores_failed++;
      libvshadow_error_free(&error);
      continue;
    }
    libvshadow_error_free(&error);
    result.stores_processed++;

    auto free_store = [&]() {
      if (store == nullptr) return;
      libvshadow_error_t* free_error = nullptr;
      if (libvshadow_store_free(&store, &free_error) != 1) {
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): store free завершился с ошибкой: {}",
                      toLibvshadowErrorMessage(free_error));
      }
      libvshadow_error_free(&free_error);
    };

    libvshadow_error_t* seek_error = nullptr;
    const off64_t seek_result =
        libvshadow_store_seek_offset(store, 0, SEEK_SET, &seek_error);
    if (seek_result < 0) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): seek store #{} завершился с ошибкой: {}",
                    store_index, toLibvshadowErrorMessage(seek_error));
      result.partial_corruption_detected = true;
      result.stores_failed++;
      libvshadow_error_free(&seek_error);
      free_store();
      continue;
    }
    libvshadow_error_free(&seek_error);

    uint64_t creation_time = 0;
    libvshadow_store_get_creation_time(store, &creation_time, nullptr);
    const std::string store_timestamp = formatReasonableFiletime(creation_time);

    const auto candidates =
        collectCandidatesFromVssStore(store, max_bytes, max_candidates);
    for (const std::string& candidate : candidates) {
      const std::string key = toLowerAscii(candidate) + "|" +
                              std::to_string(store_index) + "|" + store_timestamp;
      if (!dedup.insert(key).second) continue;

      RecoveryEvidence evidence;
      evidence.executable_path = candidate;
      evidence.source = "VSS";
      evidence.recovered_from = "VSS.native";
      evidence.timestamp = store_timestamp;

      std::ostringstream details;
      details << "store=" << store_index
              << " source=" << volume_path.filename().string()
              << " limit_bytes=" << max_bytes
              << " limit_candidates=" << max_candidates;
      evidence.details = details.str();

      result.evidence.push_back(std::move(evidence));
      if (result.evidence.size() >= max_candidates) break;
    }

    free_store();
    if (result.evidence.size() >= max_candidates) break;
  }

  free_volume();
  if (result.stores_processed == 0) {
    result.partial_corruption_detected = true;
  }
  return result;
}
#endif

}  // namespace

VSSAnalyzer::VSSAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void VSSAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();

  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(
          std::max(1, config.getInt("Recovery", "MaxCandidatesPerSource",
                                    static_cast<int>(max_candidates_per_source_))));
      vss_native_max_stores_ = static_cast<std::size_t>(
          std::max(1, config.getInt("Recovery", "VSSNativeMaxStores",
                                    static_cast<int>(vss_native_max_stores_))));
      vss_volume_path_ = config.getString("Recovery", "VSSVolumePath", "");
      unallocated_image_path_ =
          config.getString("Recovery", "UnallocatedImagePath", "");
      vss_snapshot_replay_max_files_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "VSSSnapshotReplayMaxFiles",
                           static_cast<int>(vss_snapshot_replay_max_files_))));

      for (const std::string& key :
           {"EnableVSS", "EnablePagefile", "EnableMemory", "EnableUnallocated",
            "EnableNativeVSSParser", "VSSFallbackToBinaryOnNativeFailure",
            "EnableVSSSnapshotReplay"}) {
        if (config.hasKey("Recovery", key)) {
          logger->warn(
              "Параметр [Recovery]/{} игнорируется: модуль VSS всегда активен",
              key);
        }
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки VSS");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Recovery]: {}", e.what());
  }
}

std::vector<RecoveryEvidence> VSSAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  std::size_t native_count = 0;
  std::size_t binary_count = 0;
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug,
              "VSS limits: max_bytes={} max_candidates={} native_max_stores={} "
              "snapshot_replay_max_files={}",
              max_bytes, max_candidates_per_source_, vss_native_max_stores_,
              vss_snapshot_replay_max_files_);

  bool native_attempted = false;
  bool native_success = false;
  bool native_degraded = false;
  std::size_t native_stores_processed = 0;
  std::size_t native_stores_failed = 0;

#if defined(PROGRAM_TRACES_HAVE_LIBVSHADOW) && PROGRAM_TRACES_HAVE_LIBVSHADOW
  std::vector<fs::path> volume_candidates;
  if (!vss_volume_path_.empty()) {
    const fs::path configured(vss_volume_path_);
    if (configured.is_absolute()) {
      volume_candidates.push_back(configured);
    } else {
      volume_candidates.push_back(fs::path(disk_root) / configured);
    }
  }

  std::error_code ec;
  const fs::path disk_root_path(disk_root);
  if ((fs::is_regular_file(disk_root_path, ec) && !ec) ||
      (fs::is_block_file(disk_root_path, ec) && !ec) ||
      (fs::is_character_file(disk_root_path, ec) && !ec)) {
    volume_candidates.push_back(disk_root_path);
  }

  std::sort(volume_candidates.begin(), volume_candidates.end());
  volume_candidates.erase(
      std::unique(volume_candidates.begin(), volume_candidates.end()),
      volume_candidates.end());

  if (volume_candidates.empty()) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): не найден источник тома. Укажите "
                  "[Recovery]/VSSVolumePath (raw/device) для нативного парсинга.");
  }

  for (const fs::path& candidate : volume_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    NativeVssParseResult native_result = parseVssVolumeNative(
        *resolved, max_bytes, max_candidates_per_source_, vss_native_max_stores_);
    native_attempted = native_attempted || native_result.attempted;
    native_success = native_success || native_result.success;
    native_degraded =
        native_degraded || native_result.partial_corruption_detected;
    native_stores_processed += native_result.stores_processed;
    native_stores_failed += native_result.stores_failed;
    native_count += native_result.evidence.size();
    appendUniqueEvidence(results, native_result.evidence, dedup);
  }
#else
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "VSS(native): libvshadow недоступен в текущей сборке");
#endif

  const bool run_binary_fallback =
      !native_attempted || !native_success || native_count == 0 ||
      native_degraded;

  if (native_degraded) {
    logger->warn(
        "VSS(native): detected partial corruption (stores_processed={} "
        "stores_failed={}), enabling binary fallback",
        native_stores_processed, native_stores_failed);
  }

  if (run_binary_fallback) {
    const fs::path svi_dir = fs::path(disk_root) / "System Volume Information";
    if (const auto resolved_svi = findPathCaseInsensitive(svi_dir);
        resolved_svi.has_value()) {
      std::error_code svi_ec;
      for (const auto& entry :
           fs::recursive_directory_iterator(
               *resolved_svi, fs::directory_options::skip_permission_denied, svi_ec)) {
        if (svi_ec) break;
        if (!entry.is_regular_file()) continue;
        const std::string lowered_name =
            toLowerAscii(entry.path().filename().string());
        if (lowered_name.find("shadowcopy") == std::string::npos &&
            lowered_name.find(".pf") == std::string::npos) {
          continue;
        }

        auto evidence = scanRecoveryFileBinary(entry.path(), "VSS", "VSS.binary",
                                               max_bytes,
                                               max_candidates_per_source_);
        appendVssLimits(evidence, max_bytes, max_candidates_per_source_);
        binary_count += evidence.size();
        appendUniqueEvidence(results, evidence, dedup);
      }
    }
  }

  const std::vector<fs::path> pagefile_candidates = {
      fs::path(disk_root) / "pagefile.sys",
      fs::path(disk_root) / "swapfile.sys",
      fs::path(disk_root) / "Windows" / "Temp" / "pagefile.sys"};
  for (const auto& candidate : pagefile_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    auto evidence = scanRecoveryFileBinary(*resolved, "VSS",
                                           "VSS.pagefile_binary", max_bytes,
                                           max_candidates_per_source_);
    appendVssLimits(evidence, max_bytes, max_candidates_per_source_);
    binary_count += evidence.size();
    appendUniqueEvidence(results, evidence, dedup);
  }

  const std::vector<fs::path> memory_candidates = {
      fs::path(disk_root) / "Windows" / "MEMORY.DMP",
      fs::path(disk_root) / "MEMORY.DMP"};
  for (const auto& candidate : memory_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    auto evidence = scanRecoveryFileBinary(*resolved, "VSS",
                                           "VSS.memory_dump_binary",
                                           max_bytes,
                                           max_candidates_per_source_);
    appendVssLimits(evidence, max_bytes, max_candidates_per_source_);
    binary_count += evidence.size();
    appendUniqueEvidence(results, evidence, dedup);
  }

  if (!unallocated_image_path_.empty()) {
    const fs::path image_path(unallocated_image_path_);
    std::error_code img_ec;
    if (fs::exists(image_path, img_ec) && !img_ec &&
        fs::is_regular_file(image_path, img_ec) && !img_ec) {
      auto evidence =
          scanRecoveryFileBinary(image_path, "VSS", "VSS.unallocated_binary",
                                 max_bytes, max_candidates_per_source_);
      appendVssLimits(evidence, max_bytes, max_candidates_per_source_);
      binary_count += evidence.size();
      appendUniqueEvidence(results, evidence, dedup);
    }
  }

  auto snapshot_evidence = collectSnapshotReplayEvidence(
      disk_root, max_bytes, max_candidates_per_source_,
      vss_snapshot_replay_max_files_);
  binary_count += snapshot_evidence.size();
  appendUniqueEvidence(results, snapshot_evidence, dedup);

  deduplicateVssEvidence(results);

  logger->info("Recovery(VSS/Pagefile/Memory/Unallocated): native={} binary={} "
               "total={}",
               native_count, binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
