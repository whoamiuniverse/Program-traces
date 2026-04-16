/// @file usn_analyzer.cpp
/// @brief Реализация анализатора восстановления USN/$LogFile.

#include "usn_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBFUSN) && PROGRAM_TRACES_HAVE_LIBFUSN
#include <libfusn.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;
using EvidenceUtils::toLowerAscii;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

constexpr std::size_t kMaxUsnNameBytes = 4096;
constexpr std::size_t kMaxUsnRecordSize = 65536;
constexpr uint64_t kUsnFileReferenceMask = 0x0000FFFFFFFFFFFFULL;
constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

struct NativeUsnCandidate {
  std::string name;
  uint64_t update_time = 0;
  uint64_t file_reference = 0;
  uint64_t parent_file_reference = 0;
  uint64_t update_sequence_number = 0;
  uint32_t reason_flags = 0;
  uint32_t source_flags = 0;
};

struct NativeUsnParseResult {
  bool attempted = false;
  bool success = false;
  std::size_t parsed_records = 0;
  std::vector<RecoveryEvidence> evidence;
};

/// @brief Читает little-endian `uint16_t` из буфера.
/// @param bytes Входной байтовый буфер.
/// @param offset Смещение внутри буфера.
/// @return Значение или `0`, если диапазон невалиден.
uint16_t readLeUInt16(const std::vector<uint8_t>& bytes,
                      const std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;

  uint16_t value = 0;
  value |= static_cast<uint16_t>(bytes[offset]);
  value |= static_cast<uint16_t>(bytes[offset + 1]) << 8;
  return value;
}

/// @brief Нормализует NTFS file reference до 48 бит.
/// @param reference Полный file reference.
/// @return Нормализованный идентификатор.
uint64_t normalizeFileReference(const uint64_t reference) {
  return reference & kUsnFileReferenceMask;
}

/// @brief Проверяет наличие исполняемого расширения.
/// @param value Кандидат пути/имени.
/// @return `true`, если найдено поддерживаемое расширение.
bool hasExecutableSuffix(std::string value) {
  trim(value);
  if (value.empty()) return false;
  std::ranges::replace(value, '/', '\\');
  value = toLowerAscii(std::move(value));

  for (const std::string extension :
       {".exe", ".dll", ".sys", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js",  ".msi", ".scr", ".pif"}) {
    if (value.size() >= extension.size() &&
        value.rfind(extension) == value.size() - extension.size()) {
      return true;
    }
  }
  return false;
}

/// @brief Нормализует строку пути и валидирует как исполняемый файл.
/// @param value Исходная строка.
/// @return Нормализованный путь или пустая строка, если кандидат невалиден.
std::string normalizeCandidatePath(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
  trim(value);
  if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
    value.erase(value.begin());
  }
  while (!value.empty() &&
         (value.back() == '"' || value.back() == '\'' ||
          std::isspace(static_cast<unsigned char>(value.back())) != 0)) {
    value.pop_back();
  }

  std::ranges::replace(value, '/', '\\');
  if (value.size() > 520) return {};
  if (!hasExecutableSuffix(value)) return {};
  return value;
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

/// @brief Преобразует значение флагов в hex-строку.
/// @param value Набор флагов.
/// @return Строка вида `0x...`.
std::string toHexFlags(const uint32_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::uppercase << value;
  return stream.str();
}

/// @brief Преобразует reason flags USN в человекочитаемую строку.
/// @param flags Битовое поле reason flags.
/// @return CSV-совместимое представление флагов.
std::string formatUsnReasonFlags(const uint32_t flags) {
  if (flags == 0) return "0";

  const std::array<std::pair<uint32_t, const char*>, 7> known_flags = {{
      {0x00000100U, "file_create"},
      {0x00000200U, "file_delete"},
      {0x00001000U, "rename_old"},
      {0x00002000U, "rename_new"},
      {0x00008000U, "basic_info_change"},
      {0x00100000U, "reparse_point_change"},
      {0x80000000U, "close"},
  }};

  std::string result;
  for (const auto& [flag, label] : known_flags) {
    if ((flags & flag) == 0) continue;
    if (!result.empty()) result += ",";
    result += label;
  }

  if (result.empty()) {
    result = toHexFlags(flags);
  }
  return result;
}

/// @brief Преобразует source flags USN в человекочитаемую строку.
/// @param flags Битовое поле source flags.
/// @return CSV-совместимое представление флагов.
std::string formatUsnSourceFlags(const uint32_t flags) {
  if (flags == 0) return "0";

  const std::array<std::pair<uint32_t, const char*>, 3> known_flags = {{
      {0x00000001U, "data_management"},
      {0x00000002U, "auxiliary_data"},
      {0x00000004U, "replication_management"},
  }};

  std::string result;
  for (const auto& [flag, label] : known_flags) {
    if ((flags & flag) == 0) continue;
    if (!result.empty()) result += ",";
    result += label;
  }

  if (result.empty()) {
    result = toHexFlags(flags);
  }
  return result;
}

#if defined(PROGRAM_TRACES_HAVE_LIBFUSN) && PROGRAM_TRACES_HAVE_LIBFUSN
/// @brief Конвертирует ошибку libfusn в строку.
/// @param error Указатель на объект ошибки.
/// @return Диагностическое сообщение.
std::string toLibfusnErrorMessage(libfusn_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libfusn";

  std::array<char, 2048> buffer{};
  if (libfusn_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libfusn";
}

/// @brief Извлекает UTF-8 имя из USN-записи libfusn.
/// @param record Запись USN.
/// @return Имя файла, если успешно извлечено и валидно.
std::optional<std::string> readUsnRecordNameUtf8(libfusn_record_t* record) {
  size_t utf8_size = 0;
  if (libfusn_record_get_utf8_name_size(record, &utf8_size, nullptr) != 1 ||
      utf8_size <= 1 || utf8_size > kMaxUsnNameBytes) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(utf8_size);
  if (libfusn_record_get_utf8_name(record, buffer.data(), buffer.size(),
                                   nullptr) != 1) {
    return std::nullopt;
  }

  std::string name(reinterpret_cast<char*>(buffer.data()));
  name.erase(std::remove(name.begin(), name.end(), '\0'), name.end());
  trim(name);
  if (name.empty()) return std::nullopt;
  return name;
}

/// @brief Восстанавливает путь по chain `file_reference -> parent_reference`.
/// @param file_reference Идентификатор файла.
/// @param nodes Карта узлов (name,parent).
/// @return Восстановленный относительный путь или пустая строка.
std::string reconstructUsnPath(
    const uint64_t file_reference,
    const std::unordered_map<uint64_t, std::pair<std::string, uint64_t>>&
        nodes) {
  std::vector<std::string> components;
  std::unordered_set<uint64_t> seen;

  uint64_t current = normalizeFileReference(file_reference);
  for (std::size_t depth = 0; depth < 64; ++depth) {
    const auto it = nodes.find(current);
    if (it == nodes.end()) break;
    if (!seen.insert(current).second) break;

    std::string component = it->second.first;
    trim(component);
    if (!component.empty() && component != "." && component != "..") {
      components.push_back(std::move(component));
    }

    const uint64_t parent = normalizeFileReference(it->second.second);
    if (parent == 0 || parent == current) break;
    current = parent;
  }

  if (components.empty()) return {};
  std::reverse(components.begin(), components.end());

  std::string path;
  for (const std::string& component : components) {
    if (!path.empty()) path.push_back('\\');
    path += component;
  }
  return path;
}

/// @brief Нативно парсит USN `$J` через libfusn.
/// @param file_path Путь к USN-журналу.
/// @param max_bytes Лимит чтения.
/// @param max_candidates Лимит возвращаемых кандидатов.
/// @param max_records Лимит обрабатываемых USN-записей.
/// @return Результат парсинга и найденные `RecoveryEvidence`.
NativeUsnParseResult parseUsnFileNative(const fs::path& file_path,
                                        const std::size_t max_bytes,
                                        const std::size_t max_candidates,
                                        const std::size_t max_records) {
  NativeUsnParseResult result;
  result.attempted = true;

  const auto logger = GlobalLogger::get();
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value() || data_opt->empty()) {
    return result;
  }

  libfusn_record_t* record = nullptr;
  libfusn_error_t* error = nullptr;
  if (libfusn_record_initialize(&record, &error) != 1 || record == nullptr) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "USN(native): инициализация libfusn не удалась: {}",
                  toLibfusnErrorMessage(error));
    libfusn_error_free(&error);
    return result;
  }
  libfusn_error_free(&error);

  auto free_record = [&]() {
    if (record == nullptr) return;
    libfusn_error_t* free_error = nullptr;
    if (libfusn_record_free(&record, &free_error) != 1) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "USN(native): ошибка освобождения record: {}",
                    toLibfusnErrorMessage(free_error));
    }
    libfusn_error_free(&free_error);
  };

  const std::vector<uint8_t>& data = *data_opt;
  std::unordered_map<uint64_t, std::pair<std::string, uint64_t>> nodes;
  std::vector<NativeUsnCandidate> executable_candidates;
  executable_candidates.reserve(max_candidates);
  nodes.reserve(max_records / 2);

  std::size_t parsed_records = 0;
  for (std::size_t offset = 0;
       offset + 8 <= data.size() && parsed_records < max_records;) {
    const uint32_t declared_size = readLeUInt32(data, offset);
    if (declared_size < 48 || declared_size > kMaxUsnRecordSize ||
        declared_size % 8 != 0 || offset + declared_size > data.size()) {
      ++offset;
      continue;
    }

    const uint16_t major_version = readLeUInt16(data, offset + 4);
    if (major_version < 2 || major_version > 5) {
      ++offset;
      continue;
    }

    error = nullptr;
    if (libfusn_record_copy_from_byte_stream(record, data.data() + offset,
                                             declared_size, &error) != 1) {
      libfusn_error_free(&error);
      ++offset;
      continue;
    }
    libfusn_error_free(&error);

    uint32_t actual_size = 0;
    if (libfusn_record_get_size(record, &actual_size, nullptr) != 1 ||
        actual_size < 32 || actual_size > declared_size) {
      ++offset;
      continue;
    }

    std::optional<std::string> name_opt = readUsnRecordNameUtf8(record);
    if (!name_opt.has_value()) {
      offset += actual_size;
      continue;
    }

    uint64_t update_time = 0;
    uint64_t file_reference = 0;
    uint64_t parent_reference = 0;
    uint64_t update_sequence_number = 0;
    uint32_t reason_flags = 0;
    uint32_t source_flags = 0;

    libfusn_record_get_update_time(record, &update_time, nullptr);
    libfusn_record_get_file_reference(record, &file_reference, nullptr);
    libfusn_record_get_parent_file_reference(record, &parent_reference, nullptr);
    libfusn_record_get_update_sequence_number(record, &update_sequence_number,
                                              nullptr);
    libfusn_record_get_update_reason_flags(record, &reason_flags, nullptr);
    libfusn_record_get_update_source_flags(record, &source_flags, nullptr);

    file_reference = normalizeFileReference(file_reference);
    parent_reference = normalizeFileReference(parent_reference);

    std::string name = normalizeCandidatePath(*name_opt);
    if (!name.empty()) {
      nodes[file_reference] = std::make_pair(name, parent_reference);
      if (executable_candidates.size() < max_candidates) {
        NativeUsnCandidate candidate;
        candidate.name = name;
        candidate.update_time = update_time;
        candidate.file_reference = file_reference;
        candidate.parent_file_reference = parent_reference;
        candidate.update_sequence_number = update_sequence_number;
        candidate.reason_flags = reason_flags;
        candidate.source_flags = source_flags;
        executable_candidates.push_back(std::move(candidate));
      }
    } else {
      std::string raw_name = *name_opt;
      std::ranges::replace(raw_name, '/', '\\');
      trim(raw_name);
      if (!raw_name.empty()) {
        nodes[file_reference] = std::make_pair(raw_name, parent_reference);
      }
    }

    ++parsed_records;
    offset += actual_size;
  }

  result.parsed_records = parsed_records;
  result.success = parsed_records > 0;

  std::unordered_set<std::string> seen_paths;
  for (const auto& candidate : executable_candidates) {
    std::string executable_path = candidate.name;
    if (executable_path.find('\\') == std::string::npos) {
      std::string reconstructed =
          reconstructUsnPath(candidate.file_reference, nodes);
      std::string normalized_reconstructed = normalizeCandidatePath(reconstructed);
      if (!normalized_reconstructed.empty()) {
        executable_path = std::move(normalized_reconstructed);
      }
    }

    executable_path = normalizeCandidatePath(std::move(executable_path));
    if (executable_path.empty()) continue;

    const std::string lowered = toLowerAscii(executable_path);
    if (!seen_paths.insert(lowered).second) continue;

    RecoveryEvidence evidence;
    evidence.executable_path = executable_path;
    evidence.source = "USN";
    evidence.recovered_from = "USN(native)";
    evidence.timestamp = formatReasonableFiletime(candidate.update_time);

    std::ostringstream details;
    details << file_path.filename().string() << " usn="
            << candidate.update_sequence_number
            << " reason=" << formatUsnReasonFlags(candidate.reason_flags)
            << " source=" << formatUsnSourceFlags(candidate.source_flags)
            << " frn=" << candidate.file_reference
            << " parent=" << candidate.parent_file_reference;
    evidence.details = details.str();

    result.evidence.push_back(std::move(evidence));
    if (result.evidence.size() >= max_candidates) break;
  }

  free_record();
  return result;
}
#endif

}  // namespace

USNAnalyzer::USNAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void USNAnalyzer::loadConfiguration() {
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
      native_usn_max_records_ = static_cast<std::size_t>(
          std::max(100, config.getInt("Recovery", "USNNativeMaxRecords",
                                      static_cast<int>(native_usn_max_records_))));
      usn_journal_path_ = config.getString("Recovery", "USNJournalPath", "");

      for (const std::string& key :
           {"EnableUSN", "EnableLogFile", "EnableNativeUSNParser",
            "USNFallbackToBinaryOnNativeFailure"}) {
        if (config.hasKey("Recovery", key)) {
          logger->warn(
              "Параметр [Recovery]/{} игнорируется: модуль USN всегда активен",
              key);
        }
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки USN");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Ошибка чтения [Recovery]: {}", e.what());
  }
}

std::vector<RecoveryEvidence> USNAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  std::size_t native_count = 0;
  std::size_t binary_count = 0;

  std::vector<fs::path> usn_candidates = {
      fs::path(disk_root) / "$Extend" / "$UsnJrnl:$J",
      fs::path(disk_root) / "$Extend" / "$UsnJrnl" / "$J",
      fs::path(disk_root) / "$Extend" / "$UsnJrnl",
      fs::path(disk_root) / "$UsnJrnl",
      fs::path(disk_root) / "Windows" / "$UsnJrnl"};

  if (!usn_journal_path_.empty()) {
    fs::path configured_path(usn_journal_path_);
    if (configured_path.is_absolute()) {
      usn_candidates.push_back(std::move(configured_path));
    } else {
      usn_candidates.push_back(fs::path(disk_root) / configured_path);
    }
  }

  for (const auto& candidate : usn_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    bool need_binary_fallback = true;

#if defined(PROGRAM_TRACES_HAVE_LIBFUSN) && PROGRAM_TRACES_HAVE_LIBFUSN
    NativeUsnParseResult native_result =
        parseUsnFileNative(*resolved, max_bytes, max_candidates_per_source_,
                           native_usn_max_records_);
    native_count += native_result.evidence.size();
    need_binary_fallback =
        !native_result.success || native_result.evidence.empty();
    appendUniqueEvidence(results, native_result.evidence, dedup);
#else
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "USN(native): libfusn недоступен в текущей сборке");
    need_binary_fallback = true;
#endif

    if (need_binary_fallback) {
      auto evidence =
          scanRecoveryFileBinary(*resolved, "USN", "USN(binary)", max_bytes,
                                 max_candidates_per_source_);
      binary_count += evidence.size();
      appendUniqueEvidence(results, evidence, dedup);
    }
  }

  const std::vector<fs::path> logfile_candidates = {
      fs::path(disk_root) / "$LogFile",
      fs::path(disk_root) / "Windows" / "$LogFile"};
  for (const auto& candidate : logfile_candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    auto evidence =
        scanRecoveryFileBinary(*resolved, "$LogFile", "$LogFile", max_bytes,
                               max_candidates_per_source_);
    binary_count += evidence.size();
    appendUniqueEvidence(results, evidence, dedup);
  }

  if (native_count == 0 && binary_count == 0) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "USN(native): источник не найден. Укажите [Recovery]/USNJournalPath "
                  "или предоставьте доступ к $Extend/$UsnJrnl.");
  }

  logger->info("Recovery(USN/$LogFile): native={} binary={} total={}",
               native_count, binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
