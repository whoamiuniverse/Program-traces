/// @file execution_evidence_helpers_impl.cpp
/// @brief Реализация helper-функций ExecutionEvidenceDetail.
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
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
const uint64_t kFiletimeUnixEpoch = 116444736000000000ULL;
const uint64_t kMaxReasonableFiletime = 210000000000000000ULL;
constexpr std::string_view kNetworkContextProcessKey = "__network_context__";

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
  return PathUtils::findPathCaseInsensitive(input_path);
}

/// @brief Приводит разделители пути к POSIX-варианту (`/`).
/// @param path Исходный путь.
/// @return Нормализованный путь.
std::string normalizePathSeparators(std::string path) {
  return PathUtils::normalizePathSeparators(std::move(path));
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

/// @brief Извлекает значение `key=value` из details (поиск без учета регистра).
/// @param details Строка details.
/// @param key_lower Искомый ключ в lower-case c символом `=` (например `sid=`).
/// @return Значение после ключа либо `std::nullopt`.
std::optional<std::string> extractDetailsValue(const std::string& details,
                                               const std::string& key_lower) {
  if (details.empty() || key_lower.empty()) return std::nullopt;

  const std::string lowered = toLowerAscii(details);
  const std::size_t key_pos = lowered.find(key_lower);
  if (key_pos == std::string::npos) return std::nullopt;

  std::size_t value_start = key_pos + key_lower.size();
  while (value_start < details.size() &&
         std::isspace(static_cast<unsigned char>(details[value_start])) != 0) {
    ++value_start;
  }

  std::size_t value_end = value_start;
  while (value_end < details.size()) {
    const char ch = details[value_end];
    if (ch == ',' || ch == ';') break;
    ++value_end;
  }

  std::string value = details.substr(value_start, value_end - value_start);
  trim(value);
  if (value.empty()) return std::nullopt;
  return value;
}

/// @brief Добавляет список привилегий из сырой строки в `ProcessInfo`.
/// @param info Запись процесса.
/// @param raw_privileges Строка с привилегиями.
void appendPrivileges(ProcessInfo& info, std::string raw_privileges) {
  trim(raw_privileges);
  if (raw_privileges.empty() || raw_privileges == "-") return;

  for (char& ch : raw_privileges) {
    if (ch == ',' || ch == ';' || ch == '|' || ch == '\t' || ch == '\n') {
      ch = ' ';
    }
  }

  std::istringstream stream(raw_privileges);
  std::string privilege;
  while (stream >> privilege) {
    trim(privilege);
    if (!privilege.empty() && privilege != "-") {
      appendUniqueToken(info.privileges, std::move(privilege));
    }
  }
}

/// @brief Обогащает запись процесса identity/privilege-контекстом из details.
/// @param info Запись процесса.
/// @param details Строка details.
void enrichProcessIdentityFromDetails(ProcessInfo& info,
                                      const std::string& details) {
  if (details.empty()) return;

  if (const auto user = extractDetailsValue(details, "user=");
      user.has_value()) {
    appendUniqueToken(info.users, *user);
  }
  if (const auto sid = extractDetailsValue(details, "sid=");
      sid.has_value()) {
    appendUniqueToken(info.user_sids, *sid);
  }
  if (const auto logon_id = extractDetailsValue(details, "logonid=");
      logon_id.has_value()) {
    appendUniqueToken(info.logon_ids, *logon_id);
  }
  if (const auto logon_id_alt = extractDetailsValue(details, "logon_id=");
      logon_id_alt.has_value()) {
    appendUniqueToken(info.logon_ids, *logon_id_alt);
  }
  if (const auto logon_type = extractDetailsValue(details, "logontype=");
      logon_type.has_value()) {
    appendUniqueToken(info.logon_types, *logon_type);
  }
  if (const auto logon_type_alt = extractDetailsValue(details, "logon_type=");
      logon_type_alt.has_value()) {
    appendUniqueToken(info.logon_types, *logon_type_alt);
  }

  if (const auto elevation_type = extractDetailsValue(details, "elevationtype=");
      elevation_type.has_value()) {
    if (info.elevation_type.empty()) {
      info.elevation_type = *elevation_type;
    }
  }
  if (const auto elevation_type_alt =
          extractDetailsValue(details, "tokenelevationtype=");
      elevation_type_alt.has_value()) {
    if (info.elevation_type.empty()) {
      info.elevation_type = *elevation_type_alt;
    }
  }
  if (const auto elevated_token = extractDetailsValue(details, "elevatedtoken=");
      elevated_token.has_value()) {
    if (info.elevated_token.empty()) {
      info.elevated_token = *elevated_token;
    }
  }
  if (const auto integrity_level = extractDetailsValue(details, "integritylevel=");
      integrity_level.has_value()) {
    if (info.integrity_level.empty()) {
      info.integrity_level = *integrity_level;
    }
  }
  if (const auto integrity_level_alt = extractDetailsValue(details, "mandatorylabel=");
      integrity_level_alt.has_value()) {
    if (info.integrity_level.empty()) {
      info.integrity_level = *integrity_level_alt;
    }
  }

  if (const auto privileges = extractDetailsValue(details, "privileges=");
      privileges.has_value()) {
    appendPrivileges(info, *privileges);
  }
  if (const auto privilege = extractDetailsValue(details, "privilege=");
      privilege.has_value()) {
    appendPrivileges(info, *privilege);
  }
}

/// @brief Возвращает bucket процесса, создавая его при необходимости.
/// @param process_data Общая карта процессов.
/// @param executable_path Ключ процесса (путь/имя).
/// @return Ссылка на запись процесса в карте.
ProcessInfo& ensureProcessInfo(std::unordered_map<std::string, ProcessInfo>& process_data,
                               const std::string& executable_path) {
  auto& info = process_data[executable_path];
  if (info.filename.empty()) {
    info.filename = executable_path;
  }
  return info;
}

/// @brief Сливает `source`-процесс в `target` с уникализацией ключевых полей.
/// @param target Целевая запись процесса.
/// @param source Исходная запись процесса.
void mergeProcessInfo(ProcessInfo& target, const ProcessInfo& source) {
  if (target.filename.empty()) {
    target.filename = source.filename;
  }
  if (target.command.empty()) {
    target.command = source.command;
  }

  target.run_count += source.run_count;
  target.run_times.insert(target.run_times.end(), source.run_times.begin(),
                          source.run_times.end());
  target.volumes.insert(target.volumes.end(), source.volumes.begin(),
                        source.volumes.end());
  target.metrics.insert(target.metrics.end(), source.metrics.begin(),
                        source.metrics.end());

  for (const auto& value : source.users) appendUniqueToken(target.users, value);
  for (const auto& value : source.user_sids) {
    appendUniqueToken(target.user_sids, value);
  }
  for (const auto& value : source.logon_ids) {
    appendUniqueToken(target.logon_ids, value);
  }
  for (const auto& value : source.logon_types) {
    appendUniqueToken(target.logon_types, value);
  }
  for (const auto& value : source.privileges) {
    appendUniqueToken(target.privileges, value);
  }
  for (const auto& value : source.evidence_sources) {
    appendUniqueToken(target.evidence_sources, value);
  }
  for (const auto& value : source.tamper_flags) {
    appendUniqueToken(target.tamper_flags, value);
  }
  for (const auto& value : source.timeline_artifacts) {
    appendUniqueToken(target.timeline_artifacts, value);
  }
  for (const auto& value : source.recovered_from) {
    appendUniqueToken(target.recovered_from, value);
  }

  if (target.elevation_type.empty()) {
    target.elevation_type = source.elevation_type;
  }
  if (target.elevated_token.empty()) {
    target.elevated_token = source.elevated_token;
  }
  if (target.integrity_level.empty()) {
    target.integrity_level = source.integrity_level;
  }

  updateTimestampMin(target.first_seen_utc, source.first_seen_utc);
  updateTimestampMax(target.last_seen_utc, source.last_seen_utc);
}

/// @brief Сливает карту процессов `source` в `target`.
/// @param target Целевая карта процессов.
/// @param source Исходная карта процессов.
void mergeProcessDataMaps(std::unordered_map<std::string, ProcessInfo>& target,
                          const std::unordered_map<std::string, ProcessInfo>& source) {
  for (const auto& [process_name, source_info] : source) {
    auto& target_info = ensureProcessInfo(target, process_name);
    mergeProcessInfo(target_info, source_info);
  }
}

/// @brief Добавляет единицу execution evidence в агрегированные данные процесса.
/// @param process_data Общая карта процессов.
/// @param executable_path Ключ процесса.
/// @param source Источник артефакта.
/// @param timestamp Метка времени.
/// @param details Детали для timeline.
void addExecutionEvidence(std::unordered_map<std::string, ProcessInfo>& process_data,
                          const std::string& executable_path,
                          const std::string& source,
                          const std::string& timestamp,
                          const std::string& details) {
  if (executable_path.empty()) return;

  auto& info = ensureProcessInfo(process_data, executable_path);
  appendEvidenceSource(info, source);
  addTimestamp(info, timestamp);
  appendTimelineArtifact(info, makeTimelineLabel(source, timestamp, details));
  enrichProcessIdentityFromDetails(info, details);
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

/// @brief Извлекает SID-кандидаты из строки.
/// @param line Входная строка.
/// @return Уникализированный список SID.
std::vector<std::string> extractSidCandidatesFromLine(const std::string& line) {
  std::vector<std::string> sid_candidates;
  std::string token;

  auto flush_token = [&]() {
    trim(token);
    if (looksLikeSid(token)) {
      appendUniqueToken(sid_candidates, token);
    }
    token.clear();
  };

  for (const char ch_raw : line) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    if (std::isalnum(ch) != 0 || ch_raw == '-') {
      token.push_back(ch_raw);
    } else if (!token.empty()) {
      flush_token();
    }
  }
  if (!token.empty()) {
    flush_token();
  }
  return sid_candidates;
}

/// @brief Нормализует направление firewall-правила.
/// @param raw_direction Сырое значение (`In`/`Out`/`inbound`/...).
/// @return Нормализованное направление.
std::string normalizeFirewallDirection(std::string raw_direction) {
  trim(raw_direction);
  if (raw_direction.empty()) return {};

  const std::string lowered = toLowerAscii(raw_direction);
  if (lowered == "in" || lowered == "inbound") return "inbound";
  if (lowered == "out" || lowered == "outbound") return "outbound";
  return raw_direction;
}

/// @brief Нормализует действие firewall-правила.
/// @param raw_action Сырое значение (`Allow`/`Block`/...).
/// @return Нормализованное действие.
std::string normalizeFirewallAction(std::string raw_action) {
  trim(raw_action);
  if (raw_action.empty()) return {};

  const std::string lowered = toLowerAscii(raw_action);
  if (lowered == "allow" || lowered == "allowed") return "allow";
  if (lowered == "block" || lowered == "deny" || lowered == "denied") {
    return "block";
  }
  return raw_action;
}

/// @brief Нормализует протокол firewall-правила.
/// @param raw_protocol Сырое значение протокола (число/текст).
/// @return Нормализованный протокол.
std::string normalizeFirewallProtocol(std::string raw_protocol) {
  trim(raw_protocol);
  if (raw_protocol.empty()) return {};

  const std::string lowered = toLowerAscii(raw_protocol);
  if (lowered == "6" || lowered == "tcp") return "TCP";
  if (lowered == "17" || lowered == "udp") return "UDP";
  if (lowered == "1" || lowered == "icmp") return "ICMP";
  if (lowered == "58" || lowered == "icmpv6") return "ICMPv6";
  if (lowered == "256" || lowered == "any") return "ANY";
  return raw_protocol;
}

/// @brief Парсит структуру SYSTEMTIME (16 байт) из registry binary.
/// @param binary Бинарное значение реестра.
/// @return UTC-строка в формате `YYYY-MM-DD HH:MM:SS` или `std::nullopt`.
std::optional<std::string> parseRegistrySystemTime(
    const std::vector<uint8_t>& binary) {
  if (binary.size() < 16) return std::nullopt;

  const uint16_t year = readLeUInt16Raw(binary, 0);
  const uint16_t month = readLeUInt16Raw(binary, 2);
  const uint16_t day = readLeUInt16Raw(binary, 6);
  const uint16_t hour = readLeUInt16Raw(binary, 8);
  const uint16_t minute = readLeUInt16Raw(binary, 10);
  const uint16_t second = readLeUInt16Raw(binary, 12);

  if (year < 1601 || year > 9999 || month == 0 || month > 12 || day == 0 ||
      day > 31 || hour > 23 || minute > 59 || second > 59) {
    return std::nullopt;
  }

  std::ostringstream stream;
  stream << std::setfill('0') << std::setw(4) << year << "-" << std::setw(2)
         << month << "-" << std::setw(2) << day << " " << std::setw(2) << hour
         << ":" << std::setw(2) << minute << ":" << std::setw(2) << second;
  return stream.str();
}

/// @brief Нормализует категорию профиля NetworkList.
/// @param raw_category Сырое значение категории.
/// @return Нормализованная категория (`Public/Private/DomainAuthenticated`).
std::string normalizeNetworkProfileCategory(std::string raw_category) {
  trim(raw_category);
  if (raw_category.empty()) return {};

  uint32_t category = 0;
  if (!tryParseUInt32(raw_category, category)) {
    try {
      const unsigned long parsed = std::stoul(raw_category, nullptr, 0);
      if (parsed > std::numeric_limits<uint32_t>::max()) return raw_category;
      category = static_cast<uint32_t>(parsed);
    } catch (...) {
      return raw_category;
    }
  }

  switch (category) {
    case 0:
      return "Public";
    case 1:
      return "Private";
    case 2:
      return "DomainAuthenticated";
    default:
      return std::to_string(category);
  }
}

/// @brief Парсит данные строкового firewall-правила (`k=v|...`) в map.
/// @param raw_rule Сырой текст правила.
/// @return Карта параметров (`key` в lower-case).
std::unordered_map<std::string, std::string> parseFirewallRuleData(
    std::string raw_rule) {
  std::unordered_map<std::string, std::string> fields;
  trim(raw_rule);
  if (raw_rule.empty()) return fields;

  for (std::string token : split(raw_rule, '|')) {
    trim(token);
    if (token.empty()) continue;

    const std::size_t delimiter_pos = token.find('=');
    if (delimiter_pos == std::string::npos || delimiter_pos == 0) continue;

    std::string key = token.substr(0, delimiter_pos);
    std::string value = token.substr(delimiter_pos + 1);
    trim(key);
    trim(value);
    key = toLowerAscii(std::move(key));
    if (!key.empty()) {
      fields[key] = std::move(value);
    }
  }

  return fields;
}

/// @brief Возвращает ключ процесса для глобального network-контекста.
/// @return Стабильный ключ synthetic-процесса network context.
std::string networkContextProcessKey() {
  return std::string(kNetworkContextProcessKey);
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
