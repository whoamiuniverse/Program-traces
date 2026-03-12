/// @file recovery_utils.cpp
/// @brief Реализация общих утилит recovery-анализаторов.

#include "analysis/artifacts/recovery/recovery_utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cmath>
#include <filesystem>
#include <sstream>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"

namespace WindowsDiskAnalysis::RecoveryUtils {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;

constexpr std::size_t kPeEntropyWindowBytes = 4096;
constexpr std::size_t kPePathProbeWindowBytes = 8192;
constexpr std::size_t kMaxPeCandidatesPerBuffer = 256;

/// @brief Форматирует смещение в hex-виде.
/// @param offset Смещение в байтах.
/// @return Строка вида `0x...`.
std::string formatOffsetHex(const std::uint64_t offset) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::uppercase << offset;
  return stream.str();
}

/// @brief Вычисляет энтропию Шеннона для диапазона байтов.
/// @param data Указатель на начало диапазона.
/// @param size Длина диапазона.
/// @return Энтропия (0..8).
double computeEntropy(const uint8_t* data, const std::size_t size) {
  if (data == nullptr || size == 0) return 0.0;

  std::array<std::size_t, 256> histogram{};
  for (std::size_t index = 0; index < size; ++index) {
    histogram[data[index]]++;
  }

  double entropy = 0.0;
  const double total = static_cast<double>(size);
  for (const std::size_t count : histogram) {
    if (count == 0) continue;
    const double probability = static_cast<double>(count) / total;
    entropy -= probability * std::log2(probability);
  }
  return entropy;
}

/// @brief Подбирает метку части контейнера по смещению.
/// @param offset Смещение текущего блока.
/// @param total_size Общий размер буфера.
/// @return `head`, `middle` или `tail`.
std::string inferChunkPosition(const std::size_t offset,
                               const std::size_t total_size) {
  if (total_size == 0) return "head";
  const double ratio =
      static_cast<double>(offset) / static_cast<double>(total_size);
  if (ratio < 0.33) return "head";
  if (ratio > 0.66) return "tail";
  return "middle";
}

/// @brief Формирует baseline details для recovery evidence.
/// @param container_label Метка контейнера.
/// @param method Метод извлечения.
/// @param chunk_source Тип/источник чанка.
/// @param absolute_offset Абсолютное смещение внутри контейнера.
/// @return Строка деталей.
std::string buildEvidenceDetails(const std::string& container_label,
                                 const std::string& method,
                                 const std::string& chunk_source,
                                 const std::uint64_t absolute_offset) {
  std::ostringstream stream;
  stream << "container=" << container_label;
  stream << ", method=" << method;
  stream << ", chunk=" << chunk_source;
  stream << ", offset=" << formatOffsetHex(absolute_offset);
  return stream.str();
}

/// @brief Нормализует кандидат пути из binary-carving.
/// @param executable Кандидат исполняемого файла.
/// @return Очищенный путь или пустая строка.
std::string normalizeExecutableCandidate(std::string executable) {
  executable.erase(std::remove(executable.begin(), executable.end(), '\0'),
                   executable.end());
  trim(executable);
  if (executable.empty()) return {};

  if (!executable.empty() &&
      (executable.front() == '"' || executable.front() == '\'')) {
    executable.erase(executable.begin());
  }
  while (!executable.empty() &&
         (executable.back() == '"' || executable.back() == '\'')) {
    executable.pop_back();
  }

  trim(executable);
  return executable;
}

/// @brief Добавляет запись evidence с локальной дедупликацией.
/// @param target Целевой вектор evidence.
/// @param local_dedup Набор ключей локальной дедупликации.
/// @param evidence Подготавливаемая запись.
void appendLocalUniqueEvidence(std::vector<RecoveryEvidence>& target,
                               std::unordered_set<std::string>& local_dedup,
                               RecoveryEvidence evidence) {
  if (!local_dedup.emplace(buildEvidenceDedupKey(evidence)).second) return;
  target.push_back(std::move(evidence));
}

/// @brief Добавляет ASCII-строку в lower-case напрямую в буфер ключа.
/// @param target Целевая строка-буфер.
/// @param text Исходный текст.
void appendLowerAsciiToKey(std::string& target, const std::string& text) {
  const std::size_t offset = target.size();
  target.resize(offset + text.size());
  for (std::size_t index = 0; index < text.size(); ++index) {
    const unsigned char ch = static_cast<unsigned char>(text[index]);
    target[offset + index] = static_cast<char>(std::tolower(ch));
  }
}

}  // namespace

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::findPathCaseInsensitive
std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  return PathUtils::findPathCaseInsensitive(input_path);
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::toByteLimit
std::size_t toByteLimit(const std::size_t megabytes) {
  constexpr std::size_t kMegabyte = 1024 * 1024;
  if (megabytes == 0) return kMegabyte;
  return megabytes * kMegabyte;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::scanRecoveryBufferBinary
std::vector<RecoveryEvidence> scanRecoveryBufferBinary(
    const std::vector<uint8_t>& buffer, const std::string& source,
    const std::string& recovered_from, const std::string& container_label,
    const std::string& timestamp, const std::size_t max_candidates,
    const std::uint64_t base_offset, const std::string& chunk_source,
    const std::size_t container_size) {
  std::vector<RecoveryEvidence> results;
  if (buffer.empty() || max_candidates == 0) return results;

  std::unordered_set<std::string> local_dedup;
  local_dedup.reserve(max_candidates);
  results.reserve(std::min<std::size_t>(max_candidates, 64));

  const std::size_t effective_container_size =
      container_size == 0 ? buffer.size() : container_size;
  const std::string chunk_position =
      inferChunkPosition(static_cast<std::size_t>(base_offset),
                         effective_container_size);
  const std::string normalized_chunk_source =
      chunk_source.empty() ? "buffer" : chunk_source + ":" + chunk_position;

  // 1) String-carving кандидаты.
  const auto string_candidates =
      extractExecutableCandidatesFromBinary(buffer, max_candidates * 2);
  for (const auto& raw_candidate : string_candidates) {
    if (results.size() >= max_candidates) break;

    std::string executable = normalizeExecutableCandidate(raw_candidate);
    if (executable.empty()) continue;

    RecoveryEvidence evidence;
    evidence.executable_path = std::move(executable);
    evidence.source = source;
    evidence.recovered_from = recovered_from;
    evidence.timestamp = timestamp;
    evidence.details = buildEvidenceDetails(
        container_label, "string_carving", normalized_chunk_source, base_offset);
    appendLocalUniqueEvidence(results, local_dedup, std::move(evidence));
  }

  // 2) PE-signature кандидаты с контекстом (offset + entropy + chunk source).
  std::size_t pe_hits = 0;
  for (std::size_t offset = 0;
       offset + 0x40 < buffer.size() && results.size() < max_candidates &&
       pe_hits < kMaxPeCandidatesPerBuffer;
       ++offset) {
    if (buffer[offset] != 'M' || buffer[offset + 1] != 'Z') continue;

    const uint32_t pe_header_offset = readLeUInt32(buffer, offset + 0x3c);
    if (pe_header_offset < 0x40 || pe_header_offset > 0x1000) continue;

    const std::size_t signature_offset =
        offset + static_cast<std::size_t>(pe_header_offset);
    if (signature_offset + 4 > buffer.size()) continue;
    if (buffer[signature_offset] != 'P' || buffer[signature_offset + 1] != 'E' ||
        buffer[signature_offset + 2] != 0 || buffer[signature_offset + 3] != 0) {
      continue;
    }

    const std::size_t entropy_end =
        std::min(buffer.size(), offset + kPeEntropyWindowBytes);
    const double entropy =
        computeEntropy(buffer.data() + offset, entropy_end - offset);

    const std::size_t probe_start =
        offset > (kPePathProbeWindowBytes / 2)
            ? offset - (kPePathProbeWindowBytes / 2)
            : 0;
    const std::size_t probe_end =
        std::min(buffer.size(), probe_start + kPePathProbeWindowBytes);

    std::vector<uint8_t> probe_buffer;
    probe_buffer.reserve(probe_end - probe_start);
    const auto probe_begin_it =
        buffer.begin() + static_cast<std::ptrdiff_t>(probe_start);
    const auto probe_end_it =
        buffer.begin() + static_cast<std::ptrdiff_t>(probe_end);
    probe_buffer.insert(probe_buffer.end(), probe_begin_it, probe_end_it);

    auto pe_nearby_paths =
        extractExecutableCandidatesFromBinary(probe_buffer, max_candidates);
    if (pe_nearby_paths.empty()) {
      pe_nearby_paths.emplace_back(
          "\\Recovered\\PE\\image_" +
          formatOffsetHex(base_offset + static_cast<std::uint64_t>(offset)) +
          ".exe");
    }

    for (auto& path_candidate : pe_nearby_paths) {
      if (results.size() >= max_candidates) break;
      std::string executable = normalizeExecutableCandidate(path_candidate);
      if (executable.empty()) continue;

      RecoveryEvidence evidence;
      evidence.executable_path = std::move(executable);
      evidence.source = source;
      evidence.recovered_from = recovered_from;
      evidence.timestamp = timestamp;

      std::ostringstream details;
      details << buildEvidenceDetails(
          container_label, "pe_signature", normalized_chunk_source,
          base_offset + static_cast<std::uint64_t>(offset));
      details << ", entropy=" << entropy;
      evidence.details = details.str();

      appendLocalUniqueEvidence(results, local_dedup, std::move(evidence));
    }
    pe_hits++;
  }

  return results;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::scanRecoveryFileBinary
std::vector<RecoveryEvidence> scanRecoveryFileBinary(
    const fs::path& file_path, const std::string& source,
    const std::string& recovered_from, const std::size_t max_bytes,
    const std::size_t max_candidates) {
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value() || data_opt->empty()) return {};

  std::error_code ec;
  const std::string timestamp =
      fileTimeToUtcString(fs::last_write_time(file_path, ec));
  return scanRecoveryBufferBinary(*data_opt, source, recovered_from,
                                  file_path.filename().string(), timestamp,
                                  max_candidates, 0, "file_head",
                                  data_opt->size());
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::buildEvidenceDedupKey
std::string buildEvidenceDedupKey(const RecoveryEvidence& evidence) {
  std::string key;
  key.reserve(evidence.executable_path.size() + evidence.source.size() +
              evidence.recovered_from.size() + evidence.timestamp.size() +
              evidence.details.size() + 4);

  appendLowerAsciiToKey(key, evidence.executable_path);
  key.push_back('|');
  appendLowerAsciiToKey(key, evidence.source);
  key.push_back('|');
  appendLowerAsciiToKey(key, evidence.recovered_from);
  key.push_back('|');
  key.append(evidence.timestamp);
  key.push_back('|');
  appendLowerAsciiToKey(key, evidence.details);
  return key;
}

/// @copydoc WindowsDiskAnalysis::RecoveryUtils::appendUniqueEvidence
void appendUniqueEvidence(std::vector<RecoveryEvidence>& target,
                          std::vector<RecoveryEvidence>& source,
                          std::unordered_set<std::string>& dedup_keys) {
  if (source.empty()) return;

  if (source.size() <= target.max_size() - target.size()) {
    target.reserve(target.size() + source.size());
  }
  if (source.size() <= dedup_keys.max_size() - dedup_keys.size()) {
    dedup_keys.reserve(dedup_keys.size() + source.size());
  }

  for (auto& evidence : source) {
    if (!dedup_keys.emplace(buildEvidenceDedupKey(evidence)).second) continue;
    target.push_back(std::move(evidence));
  }
}

}  // namespace WindowsDiskAnalysis::RecoveryUtils
