#include "execution_evidence_analyzer.hpp"
#include "execution_evidence_helpers.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/enums/value_type.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
#include <libesedb.h>
#endif

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

using EvidenceUtils::appendUniqueToken;
using EvidenceUtils::extractAsciiStrings;
using EvidenceUtils::extractExecutableCandidatesFromBinary;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::extractUtf16LeStrings;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::isTimestampLike;
using EvidenceUtils::readFilePrefix;
using EvidenceUtils::readLeUInt32;
using EvidenceUtils::readLeUInt64;
using EvidenceUtils::toLowerAscii;
using EvidenceUtils::updateTimestampMax;
using EvidenceUtils::updateTimestampMin;

constexpr std::string_view kDefaultKey = "Default";
constexpr uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
constexpr uint64_t kMaxReasonableFiletime = 210000000000000000ULL;

/// @brief Читает значение из секции с fallback на ключ `Default`.
/// @param config Загруженный INI-конфиг.
/// @param section Имя секции.
/// @param key Ключ для версии/режима.
/// @return Найденное строковое значение либо пустая строка.
std::string getConfigValueWithSectionDefault(const Config& config,
                                             const std::string& section,
                                             const std::string& key) {
  if (config.hasKey(section, key)) {
    return config.getString(section, key, "");
  }
  if (config.hasKey(section, std::string(kDefaultKey))) {
    return config.getString(section, std::string(kDefaultKey), "");
  }
  return {};
}

/// @brief Разрешает путь без учета регистра каждого компонента.
/// @param input_path Путь-кандидат.
/// @return Фактический путь либо `std::nullopt`.
std::optional<fs::path> findPathCaseInsensitive(const fs::path& input_path) {
  std::error_code ec;
  if (fs::exists(input_path, ec) && !ec) {
    return input_path;
  }

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

    const fs::path direct_candidate = current / component_path;
    ec.clear();
    if (fs::exists(direct_candidate, ec) && !ec) {
      current = direct_candidate;
      continue;
    }

    ec.clear();
    if (!fs::exists(current, ec) || ec || !fs::is_directory(current, ec)) {
      return std::nullopt;
    }

    const std::string component_lower = toLowerAscii(component);
    bool matched = false;
    for (const auto& entry : fs::directory_iterator(current, ec)) {
      if (ec) break;
      if (toLowerAscii(entry.path().filename().string()) == component_lower) {
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
  if (fs::exists(current, ec) && !ec) {
    return current;
  }
  return std::nullopt;
}

/// @brief Приводит разделители пути к POSIX-варианту (`/`).
/// @param path Исходный путь.
/// @return Нормализованный путь.
std::string normalizePathSeparators(std::string path) {
  std::ranges::replace(path, '\\', '/');
  return path;
}

/// @brief Добавляет уникальный источник доказательства в запись процесса.
/// @param info Структура процесса.
/// @param source Имя источника.
void appendEvidenceSource(ProcessInfo& info, const std::string& source) {
  appendUniqueToken(info.evidence_sources, source);
}

/// @brief Добавляет уникальную запись в timeline процесса.
/// @param info Структура процесса.
/// @param artifact Форматированная запись таймлайна.
void appendTimelineArtifact(ProcessInfo& info, std::string artifact) {
  appendUniqueToken(info.timeline_artifacts, std::move(artifact));
}

/// @brief Добавляет уникальный tamper-флаг в вектор.
/// @param flags Вектор флагов.
/// @param flag Флаг для добавления.
void appendTamperFlag(std::vector<std::string>& flags, std::string flag) {
  appendUniqueToken(flags, std::move(flag));
}

/// @brief Обновляет временные поля процесса по валидной метке.
/// @param info Структура процесса.
/// @param timestamp Метка времени UTC.
void addTimestamp(ProcessInfo& info, const std::string& timestamp) {
  if (!isTimestampLike(timestamp)) return;

  info.run_times.push_back(timestamp);
  updateTimestampMin(info.first_seen_utc, timestamp);
  updateTimestampMax(info.last_seen_utc, timestamp);
}

/// @brief Формирует единый label записи timeline.
/// @param source Источник артефакта.
/// @param timestamp Метка времени.
/// @param details Дополнительные детали.
/// @return Готовая строка timeline.
std::string makeTimelineLabel(const std::string& source,
                              const std::string& timestamp,
                              const std::string& details) {
  std::ostringstream stream;
  if (!timestamp.empty()) {
    stream << timestamp << " ";
  }
  stream << "[" << source << "]";
  if (!details.empty()) {
    stream << " " << details;
  }
  return stream.str();
}

/// @brief Возвращает bucket процесса, создавая его при необходимости.
/// @param process_data Общая карта процессов.
/// @param executable_path Ключ процесса (путь/имя).
/// @return Ссылка на запись процесса в карте.
ProcessInfo& ensureProcessInfo(std::map<std::string, ProcessInfo>& process_data,
                               const std::string& executable_path) {
  auto& info = process_data[executable_path];
  if (info.filename.empty()) {
    info.filename = executable_path;
  }
  return info;
}

/// @brief Добавляет единицу execution evidence в агрегированные данные процесса.
/// @param process_data Общая карта процессов.
/// @param executable_path Ключ процесса.
/// @param source Источник артефакта.
/// @param timestamp Метка времени.
/// @param details Детали для timeline.
void addExecutionEvidence(std::map<std::string, ProcessInfo>& process_data,
                          const std::string& executable_path,
                          const std::string& source,
                          const std::string& timestamp,
                          const std::string& details) {
  if (executable_path.empty()) return;

  auto& info = ensureProcessInfo(process_data, executable_path);
  appendEvidenceSource(info, source);
  addTimestamp(info, timestamp);
  appendTimelineArtifact(info, makeTimelineLabel(source, timestamp, details));
}

/// @brief Находит пользовательские hive (`NTUSER.DAT`) в профилях.
/// @param disk_root Корень Windows-раздела.
/// @return Список путей к пользовательским hive.
std::vector<fs::path> collectUserHivePaths(const std::string& disk_root) {
  std::vector<fs::path> hives;
  std::error_code ec;

  auto collect_from_users_root = [&](const fs::path& users_root) {
    ec.clear();
    if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
        ec) {
      return;
    }

    for (const auto& entry : fs::directory_iterator(users_root, ec)) {
      if (ec) break;
      if (!entry.is_directory()) continue;

      const fs::path ntuser = entry.path() / "NTUSER.DAT";
      ec.clear();
      if (fs::exists(ntuser, ec) && !ec && fs::is_regular_file(ntuser, ec)) {
        hives.push_back(ntuser);
      }
    }
  };

  collect_from_users_root(fs::path(disk_root) / "Users");
  collect_from_users_root(fs::path(disk_root) / "Documents and Settings");

  return hives;
}

/// @brief Декодирует строку, закодированную ROT13.
/// @param value Входная строка.
/// @return Декодированная строка.
std::string decodeRot13(std::string value) {
  for (char& ch : value) {
    if (ch >= 'a' && ch <= 'z') {
      ch = static_cast<char>('a' + (ch - 'a' + 13) % 26);
    } else if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>('A' + (ch - 'A' + 13) % 26);
    }
  }
  return value;
}

/// @brief Пытается извлечь индекс ControlSet из значения реестра.
/// @param value Значение `Select/Current`.
/// @return Индекс `ControlSetXXX` либо `std::nullopt`.
std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value) {
  if (!value) return std::nullopt;

  try {
    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_DWORD ||
        value->getType() ==
            RegistryAnalysis::RegistryValueType::REG_DWORD_BIG_ENDIAN) {
      return value->getAsDword();
    }
    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
      const uint64_t qword = value->getAsQword();
      if (qword <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<uint32_t>(qword);
      }
      return std::nullopt;
    }
  } catch (...) {
  }

  std::string raw = value->getDataAsString();
  trim(raw);
  uint32_t parsed = 0;
  if (tryParseUInt32(raw, parsed)) {
    return parsed;
  }
  return std::nullopt;
}

/// @brief Определяет активный ControlSet с fallback на `Select/Current`.
/// @param parser Парсер реестра.
/// @param system_hive_path Путь к SYSTEM hive.
/// @param current_control_set_path Предпочтительный путь (`CurrentControlSet`).
/// @return Имя корня control set или пустая строка.
std::string resolveControlSetRoot(RegistryAnalysis::IRegistryParser& parser,
                                  const std::string& system_hive_path,
                                  const std::string& current_control_set_path) {
  try {
    parser.listSubkeys(system_hive_path, current_control_set_path);
    return current_control_set_path;
  } catch (...) {
  }

  try {
    const auto current_value =
        parser.getSpecificValue(system_hive_path, "Select/Current");
    const auto index = parseControlSetIndex(current_value);
    if (!index.has_value()) return {};

    std::ostringstream stream;
    stream << "ControlSet" << std::setw(3) << std::setfill('0') << *index;
    return stream.str();
  } catch (...) {
    return {};
  }
}

/// @brief Ищет относительный путь в секции по версии ОС с fallback на `Default`.
/// @param config Загруженный INI-конфиг.
/// @param section Секция конфигурации.
/// @param os_version Идентификатор версии ОС.
/// @return Нормализованный относительный путь.
std::string findPathForOsVersion(const Config& config, const std::string& section,
                                 const std::string& os_version) {
  std::string value = getConfigValueWithSectionDefault(config, section, os_version);
  if (value.empty()) {
    value = getConfigValueWithSectionDefault(config, section, std::string(kDefaultKey));
  }
  return normalizePathSeparators(std::move(value));
}

/// @brief Переводит лимит в MB в байты.
/// @param mb Лимит в мегабайтах.
/// @return Лимит в байтах (минимум 1 MB).
std::size_t toByteLimit(const std::size_t mb) {
  constexpr std::size_t kMegabyte = 1024 * 1024;
  if (mb == 0) return kMegabyte;
  return mb * kMegabyte;
}

/// @brief Извлекает кандидаты исполняемых путей из первых байтов файла.
/// @param file_path Путь к файлу.
/// @param max_bytes Максимум читаемых байтов.
/// @param max_candidates Лимит кандидатов.
/// @param output Буфер-назначение.
void collectFileCandidates(const fs::path& file_path, const std::size_t max_bytes,
                           const std::size_t max_candidates,
                           std::vector<std::string>& output) {
  const auto data_opt = readFilePrefix(file_path, max_bytes);
  if (!data_opt.has_value()) return;

  const auto candidates =
      extractExecutableCandidatesFromBinary(*data_opt, max_candidates);
  output.insert(output.end(), candidates.begin(), candidates.end());
}

/// @brief Определяет username по пути к `NTUSER.DAT`.
/// @param hive_path Абсолютный путь к hive.
/// @return Имя каталога пользователя либо `unknown`.
std::string extractUsernameFromHivePath(const fs::path& hive_path) {
  const fs::path parent = hive_path.parent_path();
  const std::string name = parent.filename().string();
  return name.empty() ? "unknown" : name;
}

/// @brief Парсит строковый список из INI (`a,b,c`) в вектор значений.
/// @param raw Исходное строковое значение.
/// @return Очищенный список без пустых элементов.
std::vector<std::string> parseListSetting(std::string raw) {
  trim(raw);
  if (raw.empty()) return {};

  std::vector<std::string> values = split(raw, ',');
  for (std::string& value : values) {
    trim(value);
  }

  values.erase(std::remove_if(values.begin(), values.end(),
                              [](const std::string& value) {
                                return value.empty();
                              }),
               values.end());
  return values;
}

/// @brief Извлекает значение XML-подобного тега (`<tag>...</tag>`).
/// @param value Входной текст.
/// @param tag_name Имя тега.
/// @return Значение между тегами либо пустая строка.
std::string extractTaggedValue(std::string value, const std::string& tag_name) {
  const std::string open_tag = "<" + tag_name + ">";
  const std::string close_tag = "</" + tag_name + ">";

  const std::string lowered = toLowerAscii(value);
  const std::string open_lower = toLowerAscii(open_tag);
  const std::string close_lower = toLowerAscii(close_tag);

  const std::size_t open_pos = lowered.find(open_lower);
  if (open_pos == std::string::npos) return {};
  const std::size_t value_start = open_pos + open_tag.size();
  const std::size_t close_pos = lowered.find(close_lower, value_start);
  if (close_pos == std::string::npos || close_pos <= value_start) return {};

  value = value.substr(value_start, close_pos - value_start);
  trim(value);
  return value;
}

/// @brief Пытается извлечь путь executable из декорированного текста.
/// @param text Исходная строка с командами/тегами.
/// @return Нормализованный путь либо `std::nullopt`.
std::optional<std::string> tryExtractExecutableFromDecoratedText(std::string text) {
  trim(text);
  if (text.empty()) return std::nullopt;

  for (const std::string tag : {"Command", "ApplicationName", "AppPath",
                                "Path"}) {
    std::string tagged = extractTaggedValue(text, tag);
    if (tagged.empty()) continue;
    if (auto executable = extractExecutableFromCommand(tagged);
        executable.has_value()) {
      return executable;
    }
  }

  const std::string lowered = toLowerAscii(text);
  for (const std::string prefix :
       {"apppath=", "applicationpath=", "commandline=", "path=", "imagepath="}) {
    if (lowered.rfind(prefix, 0) == 0 && text.size() > prefix.size()) {
      std::string candidate = text.substr(prefix.size());
      trim(candidate);
      if (auto executable = extractExecutableFromCommand(candidate);
          executable.has_value()) {
        return executable;
      }
    }
  }

  return extractExecutableFromCommand(text);
}

/// @brief Извлекает читаемые ASCII/UTF-16LE строки из бинарных данных.
/// @param bytes Бинарный буфер.
/// @param min_length Минимальная длина извлекаемой строки.
/// @return Уникализированный список строк.
std::vector<std::string> collectReadableStrings(const std::vector<uint8_t>& bytes,
                                                const std::size_t min_length) {
  std::vector<std::string> values = extractAsciiStrings(bytes, min_length);
  std::vector<std::string> utf16 = extractUtf16LeStrings(bytes, min_length);
  values.insert(values.end(), utf16.begin(), utf16.end());

  std::vector<std::string> normalized;
  normalized.reserve(values.size());
  for (std::string value : values) {
    value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
    trim(value);
    if (!value.empty()) {
      normalized.push_back(std::move(value));
    }
  }
  std::sort(normalized.begin(), normalized.end());
  normalized.erase(std::unique(normalized.begin(), normalized.end()),
                   normalized.end());
  return normalized;
}

/// @brief Формирует относительный путь для поля details.
/// @param base_root Корень источника.
/// @param file_path Полный путь к артефакту.
/// @return Относительный путь или basename при ошибке.
std::string makeRelativePathForDetails(const fs::path& base_root,
                                       const fs::path& file_path) {
  std::error_code ec;
  fs::path relative = fs::relative(file_path, base_root, ec);
  if (ec) {
    relative = file_path.filename();
  }
  return normalizePathSeparators(relative.generic_string());
}

/// @brief Проверяет наличие подстроки без учета регистра.
/// @param value Исходная строка.
/// @param pattern Искомая подстрока.
/// @return `true`, если подстрока найдена.
bool containsIgnoreCase(std::string value, const std::string& pattern) {
  value = toLowerAscii(std::move(value));
  return value.find(toLowerAscii(pattern)) != std::string::npos;
}

/// @brief Проверяет наличие допустимого исполняемого расширения.
/// @param candidate Путь/имя файла.
/// @param allow_com_extension Разрешать расширение `.com`.
/// @return `true`, если расширение валидно.
bool hasExecutionExtension(const std::string& candidate,
                           const bool allow_com_extension) {
  const std::string lowered = toLowerAscii(candidate);
  for (const std::string ext : {".exe", ".bat", ".cmd", ".ps1", ".msi"}) {
    if (lowered.size() >= ext.size() &&
        lowered.rfind(ext) == lowered.size() - ext.size()) {
      return true;
    }
  }
  if (!allow_com_extension) return false;
  return lowered.size() >= 4 && lowered.rfind(".com") == lowered.size() - 4;
}

/// @brief Эвристически определяет, похожа ли строка на путь executable.
/// @param candidate Кандидат пути.
/// @param allow_com_extension Разрешать `.com`.
/// @return `true`, если строка проходит эвристики.
bool isLikelyExecutionPath(std::string candidate,
                           const bool allow_com_extension) {
  trim(candidate);
  if (candidate.empty()) return false;

  std::ranges::replace(candidate, '/', '\\');
  const std::string lowered = toLowerAscii(candidate);
  if (lowered.find("http://") != std::string::npos ||
      lowered.find("https://") != std::string::npos ||
      lowered.find("ftp://") != std::string::npos) {
    return false;
  }
  if (lowered.rfind("p:\\", 0) == 0) {
    return false;
  }
  if (!hasExecutionExtension(lowered, allow_com_extension)) {
    return false;
  }

  if (lowered.find('\\') == std::string::npos) {
    return false;
  }

  if (!allow_com_extension && lowered.size() >= 4 &&
      lowered.rfind(".com") == lowered.size() - 4) {
    return false;
  }

  return lowered.find("\\windows\\") != std::string::npos ||
         lowered.find("\\program files") != std::string::npos ||
         lowered.find("\\programdata\\") != std::string::npos ||
         lowered.find("\\users\\") != std::string::npos ||
         lowered.find("\\appdata\\") != std::string::npos ||
         lowered.find("\\system32\\") != std::string::npos ||
         lowered.find("\\syswow64\\") != std::string::npos ||
         lowered.find("\\temp\\") != std::string::npos;
}

/// @brief Проверяет, похожа ли строка на SID.
/// @param value Кандидат SID.
/// @return `true`, если формат похож на SID.
bool looksLikeSid(std::string value) {
  trim(value);
  if (value.size() < 6) return false;
  if (value.rfind("S-", 0) != 0 && value.rfind("s-", 0) != 0) return false;

  bool has_digit = false;
  for (char ch : value) {
    if (std::isdigit(static_cast<unsigned char>(ch)) != 0) {
      has_digit = true;
      continue;
    }
    if (ch == '-' || ch == 'S' || ch == 's') continue;
    return false;
  }
  return has_digit;
}

/// @brief Форматирует FILETIME в UTC только для разумного диапазона дат.
/// @param filetime Значение FILETIME.
/// @return UTC-строка либо пустая строка.
std::string formatReasonableFiletime(const uint64_t filetime) {
  if (filetime < kFiletimeUnixEpoch || filetime > kMaxReasonableFiletime) {
    return {};
  }
  return filetimeToString(filetime);
}

/// @brief Читает `uint16_t` little-endian из бинарного буфера.
/// @param bytes Буфер данных.
/// @param offset Смещение.
/// @return Значение или `0`, если диапазон невалиден.
uint16_t readLeUInt16Raw(const std::vector<uint8_t>& bytes,
                         const std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;

  uint16_t value = 0;
  value |= static_cast<uint16_t>(bytes[offset]);
  value |= static_cast<uint16_t>(bytes[offset + 1]) << 8;
  return value;
}

/// @brief Декодирует ASCII-совместимый UTF-16LE путь из бинарного блока.
/// @param bytes Входной буфер.
/// @param offset Смещение строки.
/// @param byte_size Размер строки в байтах.
/// @return Путь executable либо `std::nullopt`.
std::optional<std::string> decodeUtf16PathFromBytes(const std::vector<uint8_t>& bytes,
                                                    const std::size_t offset,
                                                    const std::size_t byte_size) {
  if (byte_size < 8 || byte_size > 4096 || byte_size % 2 != 0 ||
      offset + byte_size > bytes.size()) {
    return std::nullopt;
  }

  std::string value;
  value.reserve(byte_size / 2);
  for (std::size_t index = offset; index + 1 < offset + byte_size; index += 2) {
    const uint8_t low = bytes[index];
    const uint8_t high = bytes[index + 1];
    if (high != 0) return std::nullopt;
    if (low == 0) break;
    if (low < 32 || low > 126) return std::nullopt;
    value.push_back(static_cast<char>(low));
  }

  trim(value);
  if (value.empty()) return std::nullopt;
  std::ranges::replace(value, '/', '\\');

  if (!isLikelyExecutionPath(value, true)) return std::nullopt;
  if (auto executable = extractExecutableFromCommand(value);
      executable.has_value()) {
    return executable;
  }
  return value;
}

/// @brief Пытается извлечь timestamp рядом со структурной записью ShimCache.
/// @param bytes Бинарные данные ShimCache.
/// @param entry_offset Смещение начала записи.
/// @param path_offset Смещение пути внутри записи.
/// @param path_size Размер пути.
/// @return UTC-метка времени либо пустая строка.
std::string extractShimCacheTimestamp(const std::vector<uint8_t>& bytes,
                                      const std::size_t entry_offset,
                                      const std::size_t path_offset,
                                      const std::size_t path_size) {
  const std::array<std::size_t, 5> candidates = {
      path_offset + path_size, path_offset + path_size + 8,
      entry_offset + 8, entry_offset + 16,
      entry_offset > 8 ? entry_offset - 8 : 0};

  for (const std::size_t candidate_offset : candidates) {
    if (candidate_offset + 8 > bytes.size()) continue;
    const uint64_t filetime = readLeUInt64(bytes, candidate_offset);
    const std::string timestamp = formatReasonableFiletime(filetime);
    if (!timestamp.empty() && timestamp != "N/A") return timestamp;
  }

  return {};
}

/// @brief Извлекает структурированные кандидаты из бинарного AppCompatCache.
/// @param binary Значение `REG_BINARY` ShimCache.
/// @param max_candidates Максимум кандидатов.
/// @return Список структурных кандидатов.
std::vector<ShimCacheStructuredCandidate> parseShimCacheStructuredCandidates(
    const std::vector<uint8_t>& binary, const std::size_t max_candidates) {
  std::vector<ShimCacheStructuredCandidate> results;
  if (binary.size() < 16 || max_candidates == 0) return results;

  struct Pattern {
    std::size_t length_offset = 0;
    std::size_t length_size = 0;
    std::size_t path_offset = 0;
  };

  const std::array<Pattern, 4> patterns = {{
      {0, 2, 2},   // [u16 len][utf16 path]
      {4, 2, 6},   // [..][u16 len][utf16 path]
      {0, 4, 4},   // [u32 len][utf16 path]
      {8, 4, 12},  // [..][u32 len][utf16 path]
  }};

  std::unordered_set<std::string> seen;
  for (std::size_t offset = 0;
       offset + 12 < binary.size() && results.size() < max_candidates;) {
    bool matched = false;
    for (const Pattern& pattern : patterns) {
      if (offset + pattern.path_offset >= binary.size()) continue;

      std::size_t length = 0;
      if (pattern.length_size == 2) {
        length = readLeUInt16Raw(binary, offset + pattern.length_offset);
      } else if (pattern.length_size == 4) {
        length = static_cast<std::size_t>(
            readLeUInt32(binary, offset + pattern.length_offset));
      } else {
        continue;
      }

      if (length < 8 || length > 4096 || length % 2 != 0) continue;

      const std::size_t path_offset = offset + pattern.path_offset;
      if (path_offset + length > binary.size()) continue;

      auto path_opt = decodeUtf16PathFromBytes(binary, path_offset, length);
      if (!path_opt.has_value()) continue;

      const std::string lowered = toLowerAscii(*path_opt);
      if (!seen.insert(lowered).second) {
        offset = path_offset + length;
        matched = true;
        break;
      }

      ShimCacheStructuredCandidate candidate;
      candidate.executable_path = *path_opt;
      candidate.timestamp =
          extractShimCacheTimestamp(binary, offset, path_offset, length);
      candidate.details = "AppCompatCache(structured) offset=" +
                          std::to_string(offset);
      results.push_back(std::move(candidate));

      offset = path_offset + length;
      matched = true;
      break;
    }

    if (!matched) {
      ++offset;
    }
  }

  return results;
}

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
/// @brief Преобразует ошибку libesedb в диагностическую строку.
/// @param error Указатель на ошибку libesedb.
/// @return Текст ошибки.
std::string toLibesedbErrorMessage(libesedb_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libesedb";

  std::array<char, 2048> buffer{};
  if (libesedb_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libesedb";
}

/// @brief Санитизирует UTF-8 значение из ESE (удаление `\0` + trim).
/// @param value Исходное значение.
/// @return Нормализованная строка.
std::string sanitizeUtf8Value(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
  trim(value);
  return value;
}

/// @brief Читает UTF-8 имя колонки ESE-записи.
/// @param record Указатель на запись.
/// @param value_entry Индекс колонки.
/// @return Имя колонки либо `std::nullopt`.
std::optional<std::string> readRecordColumnNameUtf8(libesedb_record_t* record,
                                                    const int value_entry) {
  size_t name_size = 0;
  if (libesedb_record_get_utf8_column_name_size(record, value_entry, &name_size,
                                                nullptr) != 1 ||
      name_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_record_get_utf8_column_name(record, value_entry, buffer.data(),
                                           name_size, nullptr) != 1) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) return std::nullopt;
  return value;
}

/// @brief Читает UTF-8 строковое значение колонки ESE.
/// @param record Указатель на запись.
/// @param value_entry Индекс колонки.
/// @return Значение либо `std::nullopt`.
std::optional<std::string> readRecordValueUtf8(libesedb_record_t* record,
                                               const int value_entry) {
  size_t utf8_size = 0;
  const int size_result = libesedb_record_get_value_utf8_string_size(
      record, value_entry, &utf8_size, nullptr);
  if (size_result <= 0 || utf8_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(utf8_size);
  if (libesedb_record_get_value_utf8_string(record, value_entry, buffer.data(),
                                            utf8_size, nullptr) <= 0) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) return std::nullopt;
  return value;
}

/// @brief Читает бинарное значение колонки ESE.
/// @param record Указатель на запись.
/// @param value_entry Индекс колонки.
/// @return Бинарный буфер либо `std::nullopt`.
std::optional<std::vector<uint8_t>> readRecordValueBinary(
    libesedb_record_t* record, const int value_entry) {
  size_t binary_size = 0;
  const int size_result = libesedb_record_get_value_binary_data_size(
      record, value_entry, &binary_size, nullptr);
  if (size_result <= 0 || binary_size == 0) return std::nullopt;

  std::vector<uint8_t> data(binary_size);
  if (libesedb_record_get_value_binary_data(record, value_entry, data.data(),
                                            binary_size, nullptr) <= 0) {
    return std::nullopt;
  }
  return data;
}

/// @brief Читает числовое значение колонки ESE как `uint64_t`.
/// @param record Указатель на запись.
/// @param value_entry Индекс колонки.
/// @return Числовое значение либо `std::nullopt`.
std::optional<uint64_t> readRecordValueU64(libesedb_record_t* record,
                                           const int value_entry) {
  uint64_t value = 0;
  if (libesedb_record_get_value_64bit(record, value_entry, &value, nullptr) == 1) {
    return value;
  }

  uint32_t value32 = 0;
  if (libesedb_record_get_value_32bit(record, value_entry, &value32, nullptr) == 1) {
    return static_cast<uint64_t>(value32);
  }
  return std::nullopt;
}

/// @brief Читает FILETIME значение из ESE и форматирует его в UTC.
/// @param record Указатель на запись.
/// @param value_entry Индекс колонки.
/// @return UTC-метка времени либо `std::nullopt`.
std::optional<std::string> readRecordValueFiletimeString(libesedb_record_t* record,
                                                         const int value_entry) {
  uint64_t filetime = 0;
  if (libesedb_record_get_value_filetime(record, value_entry, &filetime,
                                         nullptr) != 1) {
    return std::nullopt;
  }
  const std::string timestamp = formatReasonableFiletime(filetime);
  if (timestamp.empty()) return std::nullopt;
  return timestamp;
}

/// @brief Читает UTF-8 имя таблицы ESE.
/// @param table Указатель на таблицу.
/// @return Имя таблицы либо пустая строка.
std::string getTableNameUtf8(libesedb_table_t* table) {
  size_t name_size = 0;
  if (libesedb_table_get_utf8_name_size(table, &name_size, nullptr) != 1 ||
      name_size == 0) {
    return {};
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_table_get_utf8_name(table, buffer.data(), name_size, nullptr) != 1) {
    return {};
  }

  std::string name(reinterpret_cast<char*>(buffer.data()));
  return sanitizeUtf8Value(std::move(name));
}
#endif  // defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;

ExecutionEvidenceAnalyzer::ExecutionEvidenceAnalyzer(
    std::unique_ptr<RegistryAnalysis::IRegistryParser> parser,
    std::string os_version, std::string ini_path)
    : parser_(std::move(parser)),
      os_version_(std::move(os_version)),
      ini_path_(std::move(ini_path)) {
  trim(os_version_);
  loadConfiguration();
}

void ExecutionEvidenceAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(ini_path_, false, false);

    if (!config.hasSection("ExecutionArtifacts")) {
      logger->debug("Секция [ExecutionArtifacts] не найдена, используются "
                    "значения по умолчанию");
      return;
    }

    auto readBool = [&](const std::string& key, const bool default_value) {
      try {
        return config.getBool("ExecutionArtifacts", key, default_value);
      } catch (const std::exception& e) {
        logger->warn("Некорректный параметр [ExecutionArtifacts]/{}", key);
        logger->debug("Ошибка чтения [ExecutionArtifacts]/{}: {}", key, e.what());
        return default_value;
      }
    };

    auto readSize = [&](const std::string& key, const std::size_t default_value) {
      try {
        const int value = config.getInt("ExecutionArtifacts", key,
                                        static_cast<int>(default_value));
        if (value < 0) {
          return default_value;
        }
        return static_cast<std::size_t>(value);
      } catch (...) {
        return default_value;
      }
    };

    auto readString = [&](const std::string& key, std::string default_value) {
      try {
        const std::string raw =
            config.getString("ExecutionArtifacts", key, default_value);
        return raw.empty() ? default_value : raw;
      } catch (...) {
        return default_value;
      }
    };

    auto readList = [&](const std::string& key,
                        std::vector<std::string> default_value) {
      try {
        if (!config.hasKey("ExecutionArtifacts", key)) return default_value;
        const std::string raw = config.getString("ExecutionArtifacts", key, "");
        auto parsed = parseListSetting(raw);
        return parsed.empty() ? default_value : parsed;
      } catch (...) {
        return default_value;
      }
    };

    config_.enable_shimcache =
        readBool("EnableShimCache", config_.enable_shimcache);
    config_.enable_userassist =
        readBool("EnableUserAssist", config_.enable_userassist);
    config_.enable_runmru = readBool("EnableRunMRU", config_.enable_runmru);
    config_.enable_feature_usage =
        readBool("EnableFeatureUsage", config_.enable_feature_usage);
    config_.enable_recent_apps =
        readBool("EnableRecentApps", config_.enable_recent_apps);
    config_.enable_bam_dam = readBool("EnableBamDam", config_.enable_bam_dam);
    config_.enable_jump_lists =
        readBool("EnableJumpLists", config_.enable_jump_lists);
    config_.enable_lnk_recent =
        readBool("EnableLnkRecent", config_.enable_lnk_recent);
    config_.enable_task_scheduler =
        readBool("EnableTaskScheduler", config_.enable_task_scheduler);
    config_.enable_wer = readBool("EnableWER", config_.enable_wer);
    config_.enable_ifeo = readBool("EnableIFEO", config_.enable_ifeo);
    config_.enable_timeline = readBool("EnableTimeline", config_.enable_timeline);
    config_.enable_bits = readBool("EnableBITS", config_.enable_bits);
    config_.enable_wmi_repository =
        readBool("EnableWMIRepository", config_.enable_wmi_repository);
    config_.enable_windows_search =
        readBool("EnableWindowsSearch", config_.enable_windows_search);
    config_.enable_windows_search_native_parser = readBool(
        "EnableNativeWindowsSearchParser",
        config_.enable_windows_search_native_parser);
    config_.windows_search_fallback_to_binary_on_native_failure = readBool(
        "WindowsSearchFallbackToBinaryOnNativeFailure",
        config_.windows_search_fallback_to_binary_on_native_failure);
    config_.enable_srum = readBool("EnableSRUM", config_.enable_srum);
    config_.enable_srum_native_parser =
        readBool("EnableNativeSRUM", config_.enable_srum_native_parser);
    config_.srum_fallback_to_binary_on_native_failure = readBool(
        "SrumFallbackToBinaryOnNativeFailure",
        config_.srum_fallback_to_binary_on_native_failure);
    config_.enable_security_log_tamper_check = readBool(
        "EnableSecurityLogTamperCheck", config_.enable_security_log_tamper_check);

    config_.binary_scan_max_mb =
        readSize("BinaryScanMaxMB", config_.binary_scan_max_mb);
    config_.max_candidates_per_source =
        readSize("MaxCandidatesPerSource", config_.max_candidates_per_source);
    config_.srum_native_max_records_per_table = readSize(
        "SrumNativeMaxRecordsPerTable", config_.srum_native_max_records_per_table);
    config_.windows_search_native_max_records_per_table =
        readSize("WindowsSearchNativeMaxRecordsPerTable",
                 config_.windows_search_native_max_records_per_table);

    config_.userassist_key = readString("UserAssistKey", config_.userassist_key);
    config_.runmru_key = readString("RunMRUKey", config_.runmru_key);
    config_.feature_usage_app_switched_key =
        readString("FeatureUsageAppSwitchedKey",
                   config_.feature_usage_app_switched_key);
    config_.feature_usage_show_jumpview_key =
        readString("FeatureUsageShowJumpViewKey",
                   config_.feature_usage_show_jumpview_key);
    config_.recent_apps_root_key =
        readString("RecentAppsRootKey", config_.recent_apps_root_key);
    config_.shimcache_value_path =
        readString("ShimCacheValuePath", config_.shimcache_value_path);
    config_.bam_root_path = readString("BamRootPath", config_.bam_root_path);
    config_.dam_root_path = readString("DamRootPath", config_.dam_root_path);
    config_.recent_lnk_suffix =
        readString("RecentLnkPath", config_.recent_lnk_suffix);
    config_.jump_auto_suffix = readString("JumpListAutoPath", config_.jump_auto_suffix);
    config_.jump_custom_suffix =
        readString("JumpListCustomPath", config_.jump_custom_suffix);
    config_.task_scheduler_root_path =
        readString("TaskSchedulerPath", config_.task_scheduler_root_path);
    config_.task_cache_tasks_key =
        readString("TaskCacheTasksKey", config_.task_cache_tasks_key);
    config_.ifeo_root_key = readString("IFEORootKey", config_.ifeo_root_key);
    config_.wer_programdata_path =
        readString("WERProgramDataPath", config_.wer_programdata_path);
    config_.wer_user_suffix = readString("WERUserPath", config_.wer_user_suffix);
    config_.timeline_root_suffix =
        readString("TimelineRootPath", config_.timeline_root_suffix);
    config_.bits_downloader_path =
        readString("BITSDownloaderPath", config_.bits_downloader_path);
    config_.wmi_repository_path =
        readString("WMIRepositoryPath", config_.wmi_repository_path);
    config_.windows_search_path =
        readString("WindowsSearchPath", config_.windows_search_path);
    config_.srum_path = readString("SRUMPath", config_.srum_path);
    config_.security_log_path =
        readString("SecurityLogPath", config_.security_log_path);
    config_.srum_table_allowlist =
        readList("SrumTableAllowlist", config_.srum_table_allowlist);
    config_.windows_search_table_allowlist = readList(
        "WindowsSearchTableAllowlist", config_.windows_search_table_allowlist);
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить [ExecutionArtifacts]");
    logger->debug("Ошибка чтения конфигурации ExecutionArtifacts: {}", e.what());
  }
}

std::string ExecutionEvidenceAnalyzer::resolveSoftwareHivePath(
    const std::string& disk_root) const {
  Config config(ini_path_, false, false);
  const std::string relative_path =
      findPathForOsVersion(config, "OSInfoRegistryPaths", os_version_);
  if (relative_path.empty()) return {};

  const fs::path full = fs::path(disk_root) / relative_path;
  if (const auto resolved = findPathCaseInsensitive(full); resolved.has_value()) {
    return resolved->string();
  }
  return full.string();
}

std::string ExecutionEvidenceAnalyzer::resolveSystemHivePath(
    const std::string& disk_root) const {
  Config config(ini_path_, false, false);
  const std::string relative_path =
      findPathForOsVersion(config, "OSInfoSystemRegistryPaths", os_version_);
  if (relative_path.empty()) return {};

  const fs::path full = fs::path(disk_root) / relative_path;
  if (const auto resolved = findPathCaseInsensitive(full); resolved.has_value()) {
    return resolved->string();
  }
  return full.string();
}

/// @brief Запускает этап извлечения реестровых источников исполнения.
/// @param disk_root Корень Windows-раздела.
/// @param software_hive_path Путь к SOFTWARE hive.
/// @param system_hive_path Путь к SYSTEM hive.
/// @param process_data Карта процессов для обогащения.
void ExecutionEvidenceAnalyzer::collectRegistryArtifacts(
    const std::string& disk_root, const std::string& software_hive_path,
    const std::string& system_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  if (config_.enable_shimcache && !system_hive_path.empty()) {
    collectShimCache(system_hive_path, process_data);
  }
  if (config_.enable_bam_dam && !system_hive_path.empty()) {
    collectBamDam(system_hive_path, process_data);
  }

  if (config_.enable_userassist || config_.enable_runmru) {
    collectUserAssistAndRunMru(disk_root, process_data);
  }
  if (config_.enable_feature_usage) {
    collectFeatureUsage(disk_root, process_data);
  }
  if (config_.enable_recent_apps) {
    collectRecentApps(disk_root, process_data);
  }
  if (config_.enable_task_scheduler) {
    collectTaskScheduler(disk_root, software_hive_path, process_data);
  }
  if (config_.enable_ifeo && !software_hive_path.empty()) {
    collectIfeo(software_hive_path, process_data);
  }
}

/// @brief Запускает этап извлечения файловых источников исполнения.
/// @param disk_root Корень Windows-раздела.
/// @param process_data Карта процессов для обогащения.
void ExecutionEvidenceAnalyzer::collectFilesystemArtifacts(
    const std::string& disk_root, std::map<std::string, ProcessInfo>& process_data) {
  if (config_.enable_wer) {
    collectWerReports(disk_root, process_data);
  }
  if (config_.enable_timeline) {
    collectTimeline(disk_root, process_data);
  }
  if (config_.enable_bits) {
    collectBitsQueue(disk_root, process_data);
  }
  if (config_.enable_wmi_repository) {
    collectWmiRepository(disk_root, process_data);
  }
  if (config_.enable_lnk_recent) {
    collectLnkRecent(disk_root, process_data);
  }
  if (config_.enable_jump_lists) {
    collectJumpLists(disk_root, process_data);
  }
}

/// @brief Запускает этап извлечения источников на базе ESE/бинарных БД.
/// @param disk_root Корень Windows-раздела.
/// @param process_data Карта процессов для обогащения.
void ExecutionEvidenceAnalyzer::collectDatabaseArtifacts(
    const std::string& disk_root, std::map<std::string, ProcessInfo>& process_data) {
  if (config_.enable_windows_search) {
    collectWindowsSearch(disk_root, process_data);
  }
  if (config_.enable_srum) {
    collectSrum(disk_root, process_data);
  }
}

/// @brief Запускает глобальные tamper-проверки.
/// @param disk_root Корень Windows-раздела.
/// @param global_tamper_flags Вектор глобальных tamper-флагов.
void ExecutionEvidenceAnalyzer::collectGlobalTamperSignals(
    const std::string& disk_root, std::vector<std::string>& global_tamper_flags) {
  if (config_.enable_security_log_tamper_check) {
    detectSecurityLogTampering(disk_root, global_tamper_flags);
  }
}

/// @brief Оркестрирует все этапы расширенного сбора execution evidence.
/// @param disk_root Корень Windows-раздела.
/// @param process_data Карта процессов для обогащения.
/// @param global_tamper_flags Глобальные tamper-флаги.
void ExecutionEvidenceAnalyzer::collect(
    const std::string& disk_root, std::map<std::string, ProcessInfo>& process_data,
    std::vector<std::string>& global_tamper_flags) {
  const auto logger = GlobalLogger::get();
  logger->info("Запуск расширенного анализа источников исполнения");

  const std::string software_hive_path = resolveSoftwareHivePath(disk_root);
  const std::string system_hive_path = resolveSystemHivePath(disk_root);

  collectRegistryArtifacts(disk_root, software_hive_path, system_hive_path,
                           process_data);
  collectFilesystemArtifacts(disk_root, process_data);
  collectDatabaseArtifacts(disk_root, process_data);
  collectGlobalTamperSignals(disk_root, global_tamper_flags);
}

void ExecutionEvidenceAnalyzer::collectShimCache(
    const std::string& system_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  try {
    std::string shimcache_value_path = config_.shimcache_value_path;
    const std::string control_set_root =
        resolveControlSetRoot(*parser_, system_hive_path, "CurrentControlSet");
    const std::string marker = "CurrentControlSet/";
    std::vector<std::string> value_paths;
    value_paths.push_back(shimcache_value_path);

    if (shimcache_value_path.rfind(marker, 0) == 0) {
      const std::string suffix = shimcache_value_path.substr(marker.size());
      if (!control_set_root.empty()) {
        value_paths.push_back(control_set_root + "/" + suffix);
      }
      for (int index = 1; index <= 5; ++index) {
        std::ostringstream stream;
        stream << "ControlSet" << std::setw(3) << std::setfill('0') << index
               << "/" << suffix;
        value_paths.push_back(stream.str());
      }
    }

    std::optional<std::string> last_error;
    std::unique_ptr<RegistryAnalysis::IRegistryData> value;
    for (const auto& candidate_path : value_paths) {
      try {
        value = parser_->getSpecificValue(system_hive_path, candidate_path);
        if (value) break;
      } catch (const std::exception& e) {
        last_error = e.what();
      }
    }

    if (!value) {
      if (last_error.has_value()) {
        logger->debug("ShimCache недоступен: {}", *last_error);
      }
      return;
    }

    std::size_t structured_count = 0;
    std::size_t fallback_count = 0;
    std::unordered_set<std::string> seen;

    auto append_unique = [&](const std::string& path, const std::string& timestamp,
                             const std::string& details) {
      const std::string key = toLowerAscii(path);
      if (!seen.insert(key).second) return;
      addExecutionEvidence(process_data, path, "ShimCache", timestamp, details);
    };

    if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
      const auto binary = value->getAsBinary();
      auto structured_candidates = parseShimCacheStructuredCandidates(
          binary, config_.max_candidates_per_source);

      for (const auto& candidate : structured_candidates) {
        append_unique(candidate.executable_path, candidate.timestamp,
                      candidate.details);
      }
      structured_count = structured_candidates.size();

      if (structured_candidates.empty()) {
        const auto fallback_candidates = extractExecutableCandidatesFromBinary(
            binary, config_.max_candidates_per_source);
        for (const auto& path : fallback_candidates) {
          append_unique(path, "", "AppCompatCache(binary-fallback)");
        }
        fallback_count = fallback_candidates.size();
      }
    } else {
      const auto candidates = EvidenceUtils::extractExecutableCandidatesFromStrings(
          {value->getDataAsString()}, config_.max_candidates_per_source);
      for (const auto& path : candidates) {
        append_unique(path, "", "AppCompatCache(string)");
      }
      fallback_count = candidates.size();
    }
    logger->info("ShimCache: structured={} fallback={} total={}",
                 structured_count, fallback_count, seen.size());
  } catch (const std::exception& e) {
    logger->debug("Ошибка ShimCache: {}", e.what());
  }
}

void ExecutionEvidenceAnalyzer::collectBamDam(
    const std::string& system_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  auto collect_root = [&](const std::string& root_path, const std::string& source) {
    const std::string control_set_root =
        resolveControlSetRoot(*parser_, system_hive_path, "CurrentControlSet");
    if (control_set_root.empty()) return;

    std::string normalized_root = root_path;
    const std::string marker = "CurrentControlSet/";
    if (normalized_root.rfind(marker, 0) == 0) {
      normalized_root.replace(0, marker.size(), control_set_root + "/");
    }

    std::vector<std::string> sid_subkeys;
    try {
      sid_subkeys = parser_->listSubkeys(system_hive_path, normalized_root);
    } catch (const std::exception&) {
      return;
    }

    std::size_t collected = 0;
    for (const std::string& sid : sid_subkeys) {
      const std::string sid_key = normalized_root + "/" + sid;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(system_hive_path, sid_key);
      } catch (...) {
        continue;
      }

      for (const auto& value : values) {
        std::string executable =
            getLastPathComponent(value->getName(), '/');
        if (auto parsed = extractExecutableFromCommand(executable);
            parsed.has_value()) {
          executable = *parsed;
        } else {
          continue;
        }

        std::string timestamp;
        try {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
            const auto& binary = value->getAsBinary();
            const uint64_t filetime = readLeUInt64(binary, 0);
            if (filetime >= kFiletimeUnixEpoch && filetime <= kMaxReasonableFiletime) {
              timestamp = filetimeToString(filetime);
            }
          }
        } catch (...) {
        }

        addExecutionEvidence(process_data, executable, source, timestamp,
                            source + " SID=" + sid);
        collected++;
      }
    }
    logger->info("{}: добавлено {} кандидат(ов)", source, collected);
  };

  collect_root(config_.bam_root_path, "BAM");
  collect_root(config_.dam_root_path, "DAM");
}

void ExecutionEvidenceAnalyzer::collectUserAssistAndRunMru(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(disk_root);
  if (user_hives.empty()) return;

  std::size_t userassist_count = 0;
  std::size_t runmru_count = 0;

  for (const fs::path& hive_path : user_hives) {
    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    if (config_.enable_userassist) {
      try {
        const auto guid_subkeys = parser_->listSubkeys(hive, config_.userassist_key);
        for (const std::string& guid : guid_subkeys) {
          const std::string count_key =
              config_.userassist_key + "/" + guid + "/Count";
          std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
          try {
            values = parser_->getKeyValues(hive, count_key);
          } catch (...) {
            continue;
          }

          for (const auto& value : values) {
            std::string encoded_name = getLastPathComponent(value->getName(), '/');
            if (encoded_name.empty()) continue;

            std::string decoded_name = decodeRot13(encoded_name);
            decoded_name =
                replace_all(decoded_name, "UEME_RUNPATH:", "");
            decoded_name = replace_all(decoded_name, "UEME_RUNPIDL:", "");
            trim(decoded_name);

            auto executable = extractExecutableFromCommand(decoded_name);
            if (!executable.has_value()) continue;

            uint32_t run_count = 0;
            std::string timestamp;
            if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
              const auto& binary = value->getAsBinary();
              if (binary.size() >= 8) {
                run_count = readLeUInt32(binary, 4);
              }
              if (binary.size() >= 68) {
                const uint64_t filetime = readLeUInt64(binary, 60);
                if (filetime >= kFiletimeUnixEpoch &&
                    filetime <= kMaxReasonableFiletime) {
                  timestamp = filetimeToString(filetime);
                }
              }
            }

            addExecutionEvidence(
                process_data, *executable, "UserAssist", timestamp,
                "user=" + username + ", run_count=" + std::to_string(run_count));
            userassist_count++;
          }
        }
      } catch (const std::exception& e) {
        logger->debug("UserAssist пропущен для {}: {}", hive, e.what());
      }
    }

    if (config_.enable_runmru) {
      try {
        auto values = parser_->getKeyValues(hive, config_.runmru_key);
        for (const auto& value : values) {
          std::string value_name = getLastPathComponent(value->getName(), '/');
          if (value_name.empty()) continue;
          if (toLowerAscii(value_name) == "mrulist" ||
              toLowerAscii(value_name) == "mrulistex") {
            continue;
          }

          const std::string command = value->getDataAsString();
          auto executable = extractExecutableFromCommand(command);
          if (!executable.has_value()) continue;

          addExecutionEvidence(process_data, *executable, "RunMRU", "",
                              "user=" + username + ", value=" + value_name);
          runmru_count++;
        }
      } catch (const std::exception& e) {
        logger->debug("RunMRU пропущен для {}: {}", hive, e.what());
      }
    }
  }

  logger->info("UserAssist: добавлено {} кандидат(ов)", userassist_count);
  logger->info("RunMRU: добавлено {} кандидат(ов)", runmru_count);
}

void ExecutionEvidenceAnalyzer::collectFeatureUsage(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(disk_root);
  if (user_hives.empty()) return;

  std::size_t collected = 0;
  auto collect_key = [&](const std::string& key_path, const std::string& key_tag) {
    for (const fs::path& hive_path : user_hives) {
      if (collected >= config_.max_candidates_per_source) break;

      const std::string hive = hive_path.string();
      const std::string username = extractUsernameFromHivePath(hive_path);

      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(hive, key_path);
      } catch (const std::exception& e) {
        logger->debug("FeatureUsage {} пропущен для {}: {}", key_tag, hive,
                      e.what());
        continue;
      }

      for (const auto& value : values) {
        if (collected >= config_.max_candidates_per_source) break;

        const std::string value_name = getLastPathComponent(value->getName(), '/');
        std::vector<std::string> candidates;

        if (auto executable = extractExecutableFromCommand(value_name);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }

        if (auto executable =
                tryExtractExecutableFromDecoratedText(value->getDataAsString());
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }

        std::string timestamp;
        try {
          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
            timestamp = formatReasonableFiletime(value->getAsQword());
          } else if (value->getType() ==
                         RegistryAnalysis::RegistryValueType::REG_BINARY) {
            const auto& binary = value->getAsBinary();
            if (binary.size() >= 8) {
              timestamp = formatReasonableFiletime(readLeUInt64(binary, 0));
              if (timestamp.empty() && binary.size() >= 16) {
                timestamp = formatReasonableFiletime(
                    readLeUInt64(binary, binary.size() - 8));
              }
            }

            const auto binary_candidates = extractExecutableCandidatesFromBinary(
                binary, config_.max_candidates_per_source);
            for (const auto& executable : binary_candidates) {
              appendUniqueToken(candidates, executable);
            }
          }
        } catch (...) {
        }

        for (const auto& executable : candidates) {
          if (collected >= config_.max_candidates_per_source) break;
          if (!isLikelyExecutionPath(executable)) continue;
          addExecutionEvidence(process_data, executable, "FeatureUsage", timestamp,
                              "user=" + username + ", key=" + key_tag +
                                  ", value=" + value_name);
          collected++;
        }
      }
    }
  };

  collect_key(config_.feature_usage_app_switched_key, "AppSwitched");
  collect_key(config_.feature_usage_show_jumpview_key, "ShowJumpView");
  logger->info("FeatureUsage: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectRecentApps(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::vector<fs::path> user_hives = collectUserHivePaths(disk_root);
  if (user_hives.empty()) return;

  std::size_t collected = 0;
  for (const fs::path& hive_path : user_hives) {
    if (collected >= config_.max_candidates_per_source) break;

    const std::string hive = hive_path.string();
    const std::string username = extractUsernameFromHivePath(hive_path);

    std::vector<std::string> app_subkeys;
    try {
      app_subkeys = parser_->listSubkeys(hive, config_.recent_apps_root_key);
    } catch (const std::exception& e) {
      logger->debug("RecentApps пропущен для {}: {}", hive, e.what());
      continue;
    }

    for (const std::string& app_subkey : app_subkeys) {
      if (collected >= config_.max_candidates_per_source) break;

      const std::string app_key = config_.recent_apps_root_key + "/" + app_subkey;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = parser_->getKeyValues(hive, app_key);
      } catch (...) {
        continue;
      }

      std::vector<std::string> candidates;
      std::string timestamp;
      for (const auto& value : values) {
        const std::string value_name =
            getLastPathComponent(value->getName(), '/');
        const std::string value_name_lower = toLowerAscii(value_name);

        try {
          if (timestamp.empty() &&
              (containsIgnoreCase(value_name_lower, "last") ||
               containsIgnoreCase(value_name_lower, "time"))) {
            if (value->getType() == RegistryAnalysis::RegistryValueType::REG_QWORD) {
              timestamp = formatReasonableFiletime(value->getAsQword());
            } else if (value->getType() ==
                           RegistryAnalysis::RegistryValueType::REG_BINARY &&
                       value->getAsBinary().size() >= 8) {
              timestamp = formatReasonableFiletime(
                  readLeUInt64(value->getAsBinary(), 0));
            }
          }
        } catch (...) {
        }

        if (auto executable =
                tryExtractExecutableFromDecoratedText(value->getDataAsString());
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }

        if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
          std::vector<std::string> binary_candidates =
              extractExecutableCandidatesFromBinary(
                  value->getAsBinary(), config_.max_candidates_per_source);
          for (const auto& candidate : binary_candidates) {
            appendUniqueToken(candidates, candidate);
          }
        }
      }

      for (const auto& executable : candidates) {
        if (collected >= config_.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "RecentApps", timestamp,
                            "user=" + username + ", app=" + app_subkey);
        collected++;
      }
    }
  }

  logger->info("RecentApps: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectTaskScheduler(
    const std::string& disk_root, const std::string& software_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 4 * 1024 * 1024);
  std::size_t collected = 0;

  const fs::path task_root = fs::path(disk_root) / config_.task_scheduler_root_path;
  if (const auto resolved_tasks_root = findPathCaseInsensitive(task_root);
      resolved_tasks_root.has_value()) {
    std::error_code ec;
    fs::recursive_directory_iterator iterator(*resolved_tasks_root, ec);
    fs::recursive_directory_iterator end;
    for (; iterator != end && !ec; iterator.increment(ec)) {
      if (collected >= config_.max_candidates_per_source) break;
      if (!iterator->is_regular_file(ec)) continue;

      const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
      if (!data_opt.has_value()) continue;

      std::vector<std::string> text_candidates;
      const std::vector<std::string> readable =
          collectReadableStrings(*data_opt, 4);
      for (const std::string& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(text_candidates, *executable);
        }
      }
      if (text_candidates.empty()) {
        text_candidates = extractExecutableCandidatesFromBinary(
            *data_opt, config_.max_candidates_per_source);
      }

      const std::string timestamp =
          fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
      const std::string details =
          "task=" + makeRelativePathForDetails(*resolved_tasks_root, iterator->path());
      for (const auto& executable : text_candidates) {
        if (collected >= config_.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "TaskScheduler", timestamp,
                            details);
        collected++;
      }
    }
  }

  if (!software_hive_path.empty() && collected < config_.max_candidates_per_source) {
    try {
      const auto task_ids =
          parser_->listSubkeys(software_hive_path, config_.task_cache_tasks_key);
      for (const auto& task_id : task_ids) {
        if (collected >= config_.max_candidates_per_source) break;

        const std::string task_key = config_.task_cache_tasks_key + "/" + task_id;
        std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
        try {
          values = parser_->getKeyValues(software_hive_path, task_key);
        } catch (...) {
          continue;
        }

        std::string timestamp;
        std::vector<std::string> candidates;
        for (const auto& value : values) {
          try {
            const std::string value_name =
                toLowerAscii(getLastPathComponent(value->getName(), '/'));
            if (timestamp.empty() &&
                (containsIgnoreCase(value_name, "time") ||
                 containsIgnoreCase(value_name, "date"))) {
              if (value->getType() ==
                  RegistryAnalysis::RegistryValueType::REG_QWORD) {
                timestamp = formatReasonableFiletime(value->getAsQword());
              } else if (value->getType() ==
                             RegistryAnalysis::RegistryValueType::REG_BINARY &&
                         value->getAsBinary().size() >= 8) {
                timestamp = formatReasonableFiletime(
                    readLeUInt64(value->getAsBinary(), 0));
              }
            }
          } catch (...) {
          }

          if (auto executable =
                  tryExtractExecutableFromDecoratedText(value->getDataAsString());
              executable.has_value()) {
            appendUniqueToken(candidates, *executable);
          }

          if (value->getType() == RegistryAnalysis::RegistryValueType::REG_BINARY) {
            const auto binary_candidates = extractExecutableCandidatesFromBinary(
                value->getAsBinary(), config_.max_candidates_per_source);
            for (const auto& executable : binary_candidates) {
              appendUniqueToken(candidates, executable);
            }
          }
        }

        for (const auto& executable : candidates) {
          if (collected >= config_.max_candidates_per_source) break;
          addExecutionEvidence(process_data, executable, "TaskScheduler", timestamp,
                              "taskcache=" + task_id);
          collected++;
        }
      }
    } catch (const std::exception& e) {
      logger->debug("TaskScheduler(TaskCache) пропущен: {}", e.what());
    }
  }

  logger->info("TaskScheduler: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectIfeo(
    const std::string& software_hive_path,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();

  auto normalize_target_image = [&](std::string image_name)
      -> std::optional<std::string> {
    trim(image_name);
    if (image_name.empty()) return std::nullopt;
    std::ranges::replace(image_name, '/', '\\');

    if (auto executable = extractExecutableFromCommand(image_name);
        executable.has_value()) {
      return executable;
    }

    const std::string lowered = toLowerAscii(image_name);
    for (const std::string ext : {".exe", ".com", ".bat", ".cmd", ".ps1",
                                  ".msi"}) {
      if (lowered.size() >= ext.size() &&
          lowered.rfind(ext) == lowered.size() - ext.size()) {
        return image_name;
      }
    }
    return std::nullopt;
  };

  std::size_t collected = 0;
  std::vector<std::string> image_keys;
  try {
    image_keys = parser_->listSubkeys(software_hive_path, config_.ifeo_root_key);
  } catch (const std::exception& e) {
    logger->debug("IFEO пропущен: {}", e.what());
    return;
  }

  for (const auto& image_key : image_keys) {
    if (collected >= config_.max_candidates_per_source) break;

    const auto target_opt = normalize_target_image(image_key);
    if (!target_opt.has_value()) continue;
    const std::string target = *target_opt;

    const std::string full_key = config_.ifeo_root_key + "/" + image_key;
    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
    try {
      values = parser_->getKeyValues(software_hive_path, full_key);
    } catch (...) {
      continue;
    }

    bool has_debugger = false;
    std::string debugger_command;
    std::vector<std::string> notes;

    for (const auto& value : values) {
      const std::string name = getLastPathComponent(value->getName(), '/');
      const std::string name_lower = toLowerAscii(name);
      std::string data = value->getDataAsString();
      trim(data);

      if (name_lower == "debugger" && !data.empty()) {
        has_debugger = true;
        debugger_command = data;
        notes.push_back("Debugger=" + data);
      } else if (name_lower == "globalflag" && !data.empty()) {
        notes.push_back("GlobalFlag=" + data);
      } else if ((name_lower == "verifierdlls" || name_lower == "mitigationoptions") &&
                 !data.empty()) {
        notes.push_back(name + "=" + data);
      }
    }

    if (!has_debugger && notes.empty()) continue;

    std::string details = "ifeo=" + image_key;
    if (!notes.empty()) {
      details += ", ";
      for (std::size_t i = 0; i < notes.size(); ++i) {
        if (i > 0) details += "; ";
        details += notes[i];
      }
    }
    addExecutionEvidence(process_data, target, "IFEO", "", details);
    collected++;

    if (has_debugger) {
      auto& info = ensureProcessInfo(process_data, target);
      appendTamperFlag(info.tamper_flags, "ifeo_debugger_hijack");

      if (auto debugger_executable =
              extractExecutableFromCommand(debugger_command);
          debugger_executable.has_value()) {
        addExecutionEvidence(process_data, *debugger_executable, "IFEO", "",
                            "ifeo-debugger-for=" + target);
      }
    }
  }

  logger->info("IFEO: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectWerReports(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 2 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  auto scan_wer_directory = [&](const fs::path& root_path) {
    if (collected >= config_.max_candidates_per_source) return;
    const auto resolved = findPathCaseInsensitive(root_path);
    if (!resolved.has_value()) return;

    fs::recursive_directory_iterator iterator(*resolved, ec);
    fs::recursive_directory_iterator end;
    for (; iterator != end && !ec; iterator.increment(ec)) {
      if (collected >= config_.max_candidates_per_source) break;
      if (!iterator->is_regular_file(ec)) continue;
      if (toLowerAscii(iterator->path().extension().string()) != ".wer") continue;

      const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
      if (!data_opt.has_value()) continue;

      std::vector<std::string> candidates;
      const std::vector<std::string> readable = collectReadableStrings(*data_opt, 4);
      for (std::string line : readable) {
        trim(line);
        if (line.empty()) continue;
        std::string lowered = toLowerAscii(line);
        for (const std::string prefix : {"apppath=", "applicationpath=",
                                         "commandline=", "path="}) {
          if (lowered.rfind(prefix, 0) == 0 && line.size() > prefix.size()) {
            line = line.substr(prefix.size());
            trim(line);
            break;
          }
        }
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
      if (candidates.empty()) {
        candidates = extractExecutableCandidatesFromBinary(
            *data_opt, config_.max_candidates_per_source);
      }

      const std::string timestamp =
          fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
      const std::string details =
          "wer=" + makeRelativePathForDetails(*resolved, iterator->path());
      for (const auto& executable : candidates) {
        if (collected >= config_.max_candidates_per_source) break;
        addExecutionEvidence(process_data, executable, "WER", timestamp, details);
        collected++;
      }
    }
  };

  scan_wer_directory(fs::path(disk_root) / config_.wer_programdata_path);

  for (const fs::path& users_root :
       {fs::path(disk_root) / "Users",
        fs::path(disk_root) / "Documents and Settings"}) {
    ec.clear();
    if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
        ec) {
      continue;
    }

    for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
      if (ec || collected >= config_.max_candidates_per_source) break;
      if (!user_entry.is_directory()) continue;
      scan_wer_directory(user_entry.path() / config_.wer_user_suffix);
    }
  }

  logger->info("WER: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectTimeline(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  std::size_t collected = 0;
  std::error_code ec;
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 16 * 1024 * 1024);

  for (const fs::path& users_root :
       {fs::path(disk_root) / "Users",
        fs::path(disk_root) / "Documents and Settings"}) {
    ec.clear();
    if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
        ec) {
      continue;
    }

    for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
      if (ec || collected >= config_.max_candidates_per_source) break;
      if (!user_entry.is_directory()) continue;

      const std::string username = user_entry.path().filename().string();
      const fs::path timeline_root =
          user_entry.path() / config_.timeline_root_suffix;
      const auto resolved_root = findPathCaseInsensitive(timeline_root);
      if (!resolved_root.has_value()) continue;

      fs::recursive_directory_iterator iterator(*resolved_root, ec);
      fs::recursive_directory_iterator end;
      for (; iterator != end && !ec; iterator.increment(ec)) {
        if (collected >= config_.max_candidates_per_source) break;
        if (!iterator->is_regular_file(ec)) continue;

        const std::string filename_lower =
            toLowerAscii(iterator->path().filename().string());
        const std::string ext_lower =
            toLowerAscii(iterator->path().extension().string());
        if (ext_lower != ".db" ||
            (filename_lower.find("activitiescache") == std::string::npos &&
             filename_lower.find("activitycache") == std::string::npos)) {
          continue;
        }

        const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
        if (!data_opt.has_value()) continue;

        std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
            *data_opt, config_.max_candidates_per_source);
        if (candidates.empty()) {
          const auto readable = collectReadableStrings(*data_opt, 6);
          for (const auto& line : readable) {
            if (auto executable = tryExtractExecutableFromDecoratedText(line);
                executable.has_value()) {
              appendUniqueToken(candidates, *executable);
            }
          }
        }

        const std::string timestamp =
            fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
        const std::string details =
            "timeline=" +
            makeRelativePathForDetails(*resolved_root, iterator->path()) +
            ", user=" + username;
        for (const auto& executable : candidates) {
          if (collected >= config_.max_candidates_per_source) break;
          if (!isLikelyExecutionPath(executable)) continue;
          addExecutionEvidence(process_data, executable, "Timeline", timestamp,
                              details);
          collected++;
        }
      }
    }
  }

  logger->info("Timeline: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectBitsQueue(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 16 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path bits_root = fs::path(disk_root) / config_.bits_downloader_path;
  const auto resolved_root = findPathCaseInsensitive(bits_root);
  if (!resolved_root.has_value()) {
    logger->info("BITS: добавлено 0 кандидат(ов)");
    return;
  }

  fs::recursive_directory_iterator iterator(*resolved_root, ec);
  fs::recursive_directory_iterator end;
  for (; iterator != end && !ec; iterator.increment(ec)) {
    if (collected >= config_.max_candidates_per_source) break;
    if (!iterator->is_regular_file(ec)) continue;

    const std::string filename_lower =
        toLowerAscii(iterator->path().filename().string());
    const std::string ext_lower = toLowerAscii(iterator->path().extension().string());
    const bool is_qmgr = filename_lower.rfind("qmgr", 0) == 0;
    const bool looks_like_db = ext_lower == ".dat" || ext_lower == ".db";
    if (!is_qmgr || !looks_like_db) continue;

    const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
    if (!data_opt.has_value()) continue;

    std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
        *data_opt, config_.max_candidates_per_source);
    if (candidates.empty()) {
      const auto readable = collectReadableStrings(*data_opt, 6);
      for (const auto& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
    }

    const std::string timestamp =
        fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
    const std::string details =
        "bits=" + makeRelativePathForDetails(*resolved_root, iterator->path());
    for (const auto& executable : candidates) {
      if (collected >= config_.max_candidates_per_source) break;
      if (!isLikelyExecutionPath(executable)) continue;
      addExecutionEvidence(process_data, executable, "BITS", timestamp, details);
      collected++;
    }
  }

  logger->info("BITS: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectWmiRepository(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 16 * 1024 * 1024);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path repository_root =
      fs::path(disk_root) / config_.wmi_repository_path;
  const auto resolved_root = findPathCaseInsensitive(repository_root);
  if (!resolved_root.has_value()) {
    logger->info("WMIRepository: добавлено 0 кандидат(ов)");
    return;
  }

  fs::recursive_directory_iterator iterator(*resolved_root, ec);
  fs::recursive_directory_iterator end;
  for (; iterator != end && !ec; iterator.increment(ec)) {
    if (collected >= config_.max_candidates_per_source) break;
    if (!iterator->is_regular_file(ec)) continue;

    const std::string filename_lower =
        toLowerAscii(iterator->path().filename().string());
    const std::string ext_lower = toLowerAscii(iterator->path().extension().string());
    const bool is_target = filename_lower == "objects.data" ||
                           ext_lower == ".map" || ext_lower == ".btr";
    if (!is_target) continue;

    const auto data_opt = readFilePrefix(iterator->path(), max_bytes);
    if (!data_opt.has_value()) continue;

    std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
        *data_opt, config_.max_candidates_per_source);
    if (candidates.empty()) {
      const auto readable = collectReadableStrings(*data_opt, 6);
      for (const auto& line : readable) {
        if (auto executable = tryExtractExecutableFromDecoratedText(line);
            executable.has_value()) {
          appendUniqueToken(candidates, *executable);
        }
      }
    }

    const std::string timestamp =
        fileTimeToUtcString(fs::last_write_time(iterator->path(), ec));
    const std::string details =
        "wmi=" + makeRelativePathForDetails(*resolved_root, iterator->path());
    for (const auto& executable : candidates) {
      if (collected >= config_.max_candidates_per_source) break;
      if (!isLikelyExecutionPath(executable)) continue;
      addExecutionEvidence(process_data, executable, "WMIRepository", timestamp,
                          details);
      collected++;
    }
  }

  logger->info("WMIRepository: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectWindowsSearch(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const fs::path windows_search_path =
      fs::path(disk_root) / config_.windows_search_path;
  const auto resolved = findPathCaseInsensitive(windows_search_path);
  if (!resolved.has_value()) {
    logger->info("WindowsSearch: добавлено 0 кандидат(ов)");
    return;
  }

  std::size_t collected = 0;
  bool native_attempted = false;
  if (config_.enable_windows_search_native_parser) {
    native_attempted = true;
    collected = collectWindowsSearchNative(*resolved, process_data);
    if (collected > 0) {
      logger->info("WindowsSearch(native): добавлено {} кандидат(ов)", collected);
      return;
    }
  }

  if (!config_.windows_search_fallback_to_binary_on_native_failure &&
      native_attempted) {
    logger->debug(
        "WindowsSearch fallback отключен, бинарный режим не используется после "
        "неуспеха native-парсера");
    return;
  }

  collected = collectWindowsSearchBinaryFallback(*resolved, process_data);
  logger->info("WindowsSearch(binary): добавлено {} кандидат(ов)", collected);
}

std::size_t ExecutionEvidenceAnalyzer::collectWindowsSearchBinaryFallback(
    const fs::path& windows_search_path,
    std::map<std::string, ProcessInfo>& process_data) const {
  const std::size_t max_bytes = std::min<std::size_t>(
      toByteLimit(config_.binary_scan_max_mb), 32 * 1024 * 1024);
  const auto data = readFilePrefix(windows_search_path, max_bytes);
  if (!data.has_value()) return 0;

  std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
      *data, config_.max_candidates_per_source);
  if (candidates.empty()) {
    const auto readable = collectReadableStrings(*data, 6);
    for (const auto& line : readable) {
      if (auto executable = tryExtractExecutableFromDecoratedText(line);
          executable.has_value()) {
        appendUniqueToken(candidates, *executable);
      }
    }
  }

  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(windows_search_path, ec));

  for (const auto& executable : candidates) {
    if (!isLikelyExecutionPath(executable)) continue;
    addExecutionEvidence(process_data, executable, "WindowsSearch", timestamp,
                        "search=Windows.edb (binary)");
  }
  return candidates.size();
}

std::size_t ExecutionEvidenceAnalyzer::collectWindowsSearchNative(
    const fs::path& windows_search_path,
    std::map<std::string, ProcessInfo>& process_data) {
#if !defined(PROGRAM_TRACES_HAVE_LIBESEDB) || !PROGRAM_TRACES_HAVE_LIBESEDB
  static_cast<void>(windows_search_path);
  static_cast<void>(process_data);
  return 0;
#else
  const auto logger = GlobalLogger::get();

  const std::string path_string = windows_search_path.string();
  if (path_string.empty()) return 0;

  std::unordered_set<std::string> table_allowlist_lower;
  for (std::string table_name : config_.windows_search_table_allowlist) {
    trim(table_name);
    if (!table_name.empty()) {
      table_allowlist_lower.insert(toLowerAscii(std::move(table_name)));
    }
  }

  auto is_table_allowed = [&](const std::string& table_name) {
    if (table_allowlist_lower.empty()) return true;
    return table_allowlist_lower.contains(toLowerAscii(table_name));
  };

  libesedb_file_t* file = nullptr;
  libesedb_error_t* error = nullptr;

  auto free_error = [&]() {
    if (error != nullptr) {
      libesedb_error_free(&error);
      error = nullptr;
    }
  };
  auto close_file = [&]() {
    if (file != nullptr) {
      libesedb_file_close(file, nullptr);
      libesedb_file_free(&file, nullptr);
      file = nullptr;
    }
  };

  if (libesedb_file_initialize(&file, &error) != 1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug(
        "WindowsSearch(native): не удалось инициализировать libesedb: {}",
        details);
    return 0;
  }

  if (libesedb_file_open(file, path_string.c_str(), LIBESEDB_OPEN_READ, &error) !=
      1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->warn("WindowsSearch(native): не удалось открыть \"{}\" ({})",
                 path_string, details);
    return 0;
  }

  int number_of_tables = 0;
  if (libesedb_file_get_number_of_tables(file, &number_of_tables, &error) != 1 ||
      number_of_tables <= 0) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug(
        "WindowsSearch(native): не удалось получить список таблиц: {}",
        details);
    return 0;
  }
  free_error();

  std::size_t collected = 0;
  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    if (collected >= config_.max_candidates_per_source) break;

    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    if (!is_table_allowed(table_name)) {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        config_.windows_search_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      if (collected >= config_.max_candidates_per_source) break;

      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::string row_timestamp;
      std::vector<std::string> row_executables;
      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";

          if (auto filetime_value =
                  readRecordValueFiletimeString(record, value_entry);
              filetime_value.has_value() &&
              (row_timestamp.empty() ||
               containsIgnoreCase(column_name, "time") ||
               containsIgnoreCase(column_name, "date") ||
               containsIgnoreCase(column_name, "stamp"))) {
            row_timestamp = *filetime_value;
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            if (auto executable = extractExecutableFromCommand(*text);
                executable.has_value()) {
              appendUniqueToken(row_executables, *executable);
            }
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            const auto candidates = extractExecutableCandidatesFromBinary(
                *binary, config_.max_candidates_per_source);
            for (const auto& executable : candidates) {
              appendUniqueToken(row_executables, executable);
            }
          }
        }
      }

      libesedb_record_free(&record, nullptr);
      if (row_executables.empty()) continue;

      for (const auto& executable : row_executables) {
        if (collected >= config_.max_candidates_per_source) break;
        if (!isLikelyExecutionPath(executable)) continue;
        addExecutionEvidence(process_data, executable, "WindowsSearch",
                            row_timestamp, "table=" + table_name);
        collected++;
      }
    }

    libesedb_table_free(&table, nullptr);
  }

  close_file();
  return collected;
#endif
}

void ExecutionEvidenceAnalyzer::collectLnkRecent(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  const fs::path users_root = fs::path(disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;

    const fs::path recent_dir = user_entry.path() / config_.recent_lnk_suffix;
    ec.clear();
    if (!fs::exists(recent_dir, ec) || ec || !fs::is_directory(recent_dir, ec) ||
        ec) {
      continue;
    }

    for (const auto& file_entry : fs::directory_iterator(recent_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;
      if (toLowerAscii(file_entry.path().extension().string()) != ".lnk") continue;

      std::vector<std::string> candidates;
      collectFileCandidates(file_entry.path(), max_bytes,
                            config_.max_candidates_per_source, candidates);
      if (candidates.empty()) {
        if (auto fallback = extractExecutableFromCommand(
                file_entry.path().filename().string());
            fallback.has_value()) {
          candidates.push_back(*fallback);
        }
      }

      const std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      const std::string details = "lnk=" + file_entry.path().filename().string();

      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "LNKRecent", timestamp,
                            details);
        collected++;
      }
    }
  }

  logger->info("LNK Recent: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectJumpLists(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  auto process_jump_dir = [&](const fs::path& jump_dir) {
    ec.clear();
    if (!fs::exists(jump_dir, ec) || ec || !fs::is_directory(jump_dir, ec) || ec) {
      return;
    }

    for (const auto& file_entry : fs::directory_iterator(jump_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;

      const std::string ext = toLowerAscii(file_entry.path().extension().string());
      if (ext != ".automaticdestinations-ms" && ext != ".customdestinations-ms") {
        continue;
      }

      std::vector<std::string> candidates;
      collectFileCandidates(file_entry.path(), max_bytes,
                            config_.max_candidates_per_source, candidates);

      const std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      const std::string details = "jump=" + file_entry.path().filename().string();
      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "JumpList", timestamp,
                            details);
        collected++;
      }
    }
  };

  const fs::path users_root = fs::path(disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;
    process_jump_dir(user_entry.path() / config_.jump_auto_suffix);
    process_jump_dir(user_entry.path() / config_.jump_custom_suffix);
  }

  logger->info("Jump Lists: добавлено {} кандидат(ов)", collected);
}

void ExecutionEvidenceAnalyzer::collectSrum(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data) {
  const auto logger = GlobalLogger::get();
  const fs::path srum_path = fs::path(disk_root) / config_.srum_path;
  const auto resolved = findPathCaseInsensitive(srum_path);
  if (!resolved.has_value()) return;

  std::size_t collected = 0;
  bool native_attempted = false;

  if (config_.enable_srum_native_parser) {
    native_attempted = true;
    collected = collectSrumNative(*resolved, process_data);
    if (collected > 0) {
      logger->info("SRUM(native): добавлено {} кандидат(ов)", collected);
      return;
    }
  }

  if (!config_.srum_fallback_to_binary_on_native_failure &&
      native_attempted) {
    logger->debug(
        "SRUM fallback отключен, бинарный режим не используется после "
        "неуспеха native-парсера");
    return;
  }

  collected = collectSrumBinaryFallback(*resolved, process_data);
  logger->info("SRUM(binary): добавлено {} кандидат(ов)", collected);
}

std::size_t ExecutionEvidenceAnalyzer::collectSrumBinaryFallback(
    const fs::path& srum_path,
    std::map<std::string, ProcessInfo>& process_data) const {
  const std::size_t max_bytes = toByteLimit(config_.binary_scan_max_mb);
  const auto data = readFilePrefix(srum_path, max_bytes);
  if (!data.has_value()) return 0;

  const std::vector<std::string> candidates = extractExecutableCandidatesFromBinary(
      *data, config_.max_candidates_per_source);
  std::error_code ec;
  const std::string timestamp = fileTimeToUtcString(
      fs::last_write_time(srum_path, ec));

  for (const auto& executable : candidates) {
    addExecutionEvidence(process_data, executable, "SRUM", timestamp,
                        "sru=SRUDB.dat (binary)");
  }
  return candidates.size();
}

std::size_t ExecutionEvidenceAnalyzer::collectSrumNative(
    const fs::path& srum_path,
    std::map<std::string, ProcessInfo>& process_data) {
#if !defined(PROGRAM_TRACES_HAVE_LIBESEDB) || !PROGRAM_TRACES_HAVE_LIBESEDB
  static_cast<void>(srum_path);
  static_cast<void>(process_data);
  return 0;
#else
  const auto logger = GlobalLogger::get();

  const std::string path_string = srum_path.string();
  if (path_string.empty()) return 0;

  std::unordered_set<std::string> table_allowlist_lower;
  for (std::string table_name : config_.srum_table_allowlist) {
    trim(table_name);
    if (!table_name.empty()) {
      table_allowlist_lower.insert(toLowerAscii(std::move(table_name)));
    }
  }

  auto is_table_allowed = [&](const std::string& table_name) {
    if (table_allowlist_lower.empty()) return true;
    return table_allowlist_lower.contains(toLowerAscii(table_name));
  };

  libesedb_file_t* file = nullptr;
  libesedb_error_t* error = nullptr;

  auto free_error = [&]() {
    if (error != nullptr) {
      libesedb_error_free(&error);
      error = nullptr;
    }
  };
  auto close_file = [&]() {
    if (file != nullptr) {
      libesedb_file_close(file, nullptr);
      libesedb_file_free(&file, nullptr);
      file = nullptr;
    }
  };

  if (libesedb_file_initialize(&file, &error) != 1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug("SRUM(native): не удалось инициализировать libesedb: {}",
                  details);
    return 0;
  }

  if (libesedb_file_open(file, path_string.c_str(), LIBESEDB_OPEN_READ, &error) !=
      1) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->warn("SRUM(native): не удалось открыть \"{}\" ({})", path_string,
                 details);
    return 0;
  }

  int number_of_tables = 0;
  if (libesedb_file_get_number_of_tables(file, &number_of_tables, &error) != 1 ||
      number_of_tables <= 0) {
    const std::string details = toLibesedbErrorMessage(error);
    free_error();
    close_file();
    logger->debug("SRUM(native): не удалось получить список таблиц: {}",
                  details);
    return 0;
  }
  free_error();

  std::unordered_map<uint64_t, std::string> id_map;

  auto parse_id_map_table = [&](libesedb_table_t* table) {
    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      return;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        config_.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::optional<uint64_t> id_index;
      std::vector<std::string> values;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (!id_index.has_value() &&
              (column_lower == "idindex" || column_lower == "id_index" ||
               column_lower == "id")) {
            id_index = readRecordValueU64(record, value_entry);
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            values.push_back(*text);
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            auto ascii_strings = extractAsciiStrings(*binary, 6);
            auto utf16_strings = extractUtf16LeStrings(*binary, 6);
            values.insert(values.end(), ascii_strings.begin(), ascii_strings.end());
            values.insert(values.end(), utf16_strings.begin(), utf16_strings.end());
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (!id_index.has_value()) continue;

      std::string best_value;
      for (std::string value : values) {
        value = sanitizeUtf8Value(std::move(value));
        if (value.empty()) continue;
        if (looksLikeSid(value)) {
          best_value = value;
          break;
        }
        if (auto executable = extractExecutableFromCommand(value);
            executable.has_value()) {
          best_value = *executable;
          break;
        }
      }

      if (!best_value.empty()) {
        id_map[*id_index] = best_value;
      }
    }
  };

  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      parse_id_map_table(table);
    }

    libesedb_table_free(&table, nullptr);
  }

  std::size_t collected = 0;
  for (int table_entry = 0; table_entry < number_of_tables; ++table_entry) {
    if (collected >= config_.max_candidates_per_source) break;

    libesedb_table_t* table = nullptr;
    if (libesedb_file_get_table(file, table_entry, &table, nullptr) != 1 ||
        table == nullptr) {
      continue;
    }

    const std::string table_name = getTableNameUtf8(table);
    const std::string table_lower = toLowerAscii(table_name);

    if (!is_table_allowed(table_name)) {
      libesedb_table_free(&table, nullptr);
      continue;
    }
    if (table_lower.find("idmap") != std::string::npos ||
        table_lower == "srudbidmaptable") {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    int number_of_records = 0;
    if (libesedb_table_get_number_of_records(table, &number_of_records,
                                             nullptr) != 1 ||
        number_of_records <= 0) {
      libesedb_table_free(&table, nullptr);
      continue;
    }

    const int record_limit = static_cast<int>(std::min<std::size_t>(
        static_cast<std::size_t>(number_of_records),
        config_.srum_native_max_records_per_table));

    for (int record_entry = 0; record_entry < record_limit; ++record_entry) {
      if (collected >= config_.max_candidates_per_source) break;

      libesedb_record_t* record = nullptr;
      if (libesedb_table_get_record(table, record_entry, &record, nullptr) != 1 ||
          record == nullptr) {
        continue;
      }

      std::string row_timestamp;
      std::string row_sid;
      std::vector<std::string> row_executables;

      int value_count = 0;
      if (libesedb_record_get_number_of_values(record, &value_count, nullptr) ==
          1) {
        for (int value_entry = 0; value_entry < value_count; ++value_entry) {
          const auto column_name_opt =
              readRecordColumnNameUtf8(record, value_entry);
          const std::string column_name =
              column_name_opt.has_value() ? *column_name_opt : "";
          const std::string column_lower = toLowerAscii(column_name);

          if (auto filetime_value =
                  readRecordValueFiletimeString(record, value_entry);
              filetime_value.has_value() &&
              (row_timestamp.empty() ||
               containsIgnoreCase(column_name, "time") ||
               containsIgnoreCase(column_name, "date") ||
               containsIgnoreCase(column_name, "stamp"))) {
            row_timestamp = *filetime_value;
          }

          if (auto text = readRecordValueUtf8(record, value_entry);
              text.has_value()) {
            std::string value = *text;
            if (row_sid.empty() && looksLikeSid(value) &&
                (containsIgnoreCase(column_name, "sid") ||
                 containsIgnoreCase(column_name, "user"))) {
              row_sid = value;
            }

            if (auto executable = extractExecutableFromCommand(value);
                executable.has_value()) {
              appendUniqueToken(row_executables, *executable);
            }
          }

          if (auto numeric_value = readRecordValueU64(record, value_entry);
              numeric_value.has_value()) {
            if (const auto it = id_map.find(*numeric_value); it != id_map.end()) {
              if (row_sid.empty() && looksLikeSid(it->second)) {
                row_sid = it->second;
              }
              if (auto executable = extractExecutableFromCommand(it->second);
                  executable.has_value()) {
                appendUniqueToken(row_executables, *executable);
              }
            }
          }

          if (auto binary = readRecordValueBinary(record, value_entry);
              binary.has_value()) {
            const auto binary_candidates = extractExecutableCandidatesFromBinary(
                *binary, config_.max_candidates_per_source);
            for (const auto& executable : binary_candidates) {
              appendUniqueToken(row_executables, executable);
            }

            if (row_sid.empty()) {
              auto ascii_strings = extractAsciiStrings(*binary, 6);
              auto utf16_strings = extractUtf16LeStrings(*binary, 6);
              ascii_strings.insert(ascii_strings.end(), utf16_strings.begin(),
                                   utf16_strings.end());
              for (std::string candidate : ascii_strings) {
                candidate = sanitizeUtf8Value(std::move(candidate));
                if (looksLikeSid(candidate)) {
                  row_sid = candidate;
                  break;
                }
              }
            }
          }
        }
      }

      libesedb_record_free(&record, nullptr);

      if (row_executables.empty()) continue;
      for (const auto& executable : row_executables) {
        if (collected >= config_.max_candidates_per_source) break;

        std::string details = "table=" + table_name;
        if (!row_sid.empty()) {
          details += ", sid=" + row_sid;
        }
        addExecutionEvidence(process_data, executable, "SRUM", row_timestamp,
                            details);
        collected++;
      }
    }

    libesedb_table_free(&table, nullptr);
  }

  close_file();
  return collected;
#endif
}

void ExecutionEvidenceAnalyzer::detectSecurityLogTampering(
    const std::string& disk_root, std::vector<std::string>& global_tamper_flags) {
  const auto logger = GlobalLogger::get();

  const fs::path security_log = fs::path(disk_root) / config_.security_log_path;
  const auto resolved = findPathCaseInsensitive(security_log);
  if (!resolved.has_value()) return;

  try {
    EventLogAnalysis::EvtxParser parser;
    auto events = parser.getEventsByType(resolved->string(), 1102);
    if (!events.empty()) {
      appendTamperFlag(global_tamper_flags, "security_log_cleared");
      logger->warn("Обнаружены события очистки журнала Security (ID 1102)");
    }
  } catch (const std::exception& e) {
    logger->debug("Проверка security_log_cleared пропущена: {}", e.what());
  }
}

}  // namespace WindowsDiskAnalysis
