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
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

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
  // Use case-insensitive key so that e.g. "SVCHOST.EXE" (EventLog) merges
  // with "svchost.exe" (Prefetch) instead of creating a duplicate entry.
  const std::string key = to_lower(executable_path);
  auto& info = process_data[key];
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

/// @brief Сливает временный `source`-процесс в `target`, двигая данные при возможности.
/// @param target Целевая запись процесса.
/// @param source Временная запись процесса.
void mergeProcessInfo(ProcessInfo& target, ProcessInfo&& source) {
  if (target.filename.empty()) {
    target.filename = std::move(source.filename);
  }
  if (target.command.empty()) {
    target.command = std::move(source.command);
  }

  target.run_count += source.run_count;
  target.run_times.insert(target.run_times.end(),
                          std::make_move_iterator(source.run_times.begin()),
                          std::make_move_iterator(source.run_times.end()));
  target.volumes.insert(target.volumes.end(),
                        std::make_move_iterator(source.volumes.begin()),
                        std::make_move_iterator(source.volumes.end()));
  target.metrics.insert(target.metrics.end(),
                        std::make_move_iterator(source.metrics.begin()),
                        std::make_move_iterator(source.metrics.end()));

  for (auto& value : source.users) appendUniqueToken(target.users, std::move(value));
  for (auto& value : source.user_sids) {
    appendUniqueToken(target.user_sids, std::move(value));
  }
  for (auto& value : source.logon_ids) {
    appendUniqueToken(target.logon_ids, std::move(value));
  }
  for (auto& value : source.logon_types) {
    appendUniqueToken(target.logon_types, std::move(value));
  }
  for (auto& value : source.privileges) {
    appendUniqueToken(target.privileges, std::move(value));
  }
  for (auto& value : source.evidence_sources) {
    appendUniqueToken(target.evidence_sources, std::move(value));
  }
  for (auto& value : source.timeline_artifacts) {
    appendUniqueToken(target.timeline_artifacts, std::move(value));
  }
  for (auto& value : source.recovered_from) {
    appendUniqueToken(target.recovered_from, std::move(value));
  }

  if (target.elevation_type.empty()) {
    target.elevation_type = std::move(source.elevation_type);
  }
  if (target.elevated_token.empty()) {
    target.elevated_token = std::move(source.elevated_token);
  }
  if (target.integrity_level.empty()) {
    target.integrity_level = std::move(source.integrity_level);
  }

  updateTimestampMin(target.first_seen_utc, source.first_seen_utc);
  updateTimestampMax(target.last_seen_utc, source.last_seen_utc);
}

/// @brief Сливает карту процессов `source` в `target`.
/// @param target Целевая карта процессов.
/// @param source Исходная карта процессов.
void mergeProcessDataMaps(std::unordered_map<std::string, ProcessInfo>& target,
                          const std::unordered_map<std::string, ProcessInfo>& source) {
  target.reserve(target.size() + source.size());
  for (const auto& [process_name, source_info] : source) {
    if (auto it = target.find(process_name); it == target.end()) {
      auto [inserted_it, _] = target.emplace(process_name, source_info);
      if (inserted_it->second.filename.empty()) {
        inserted_it->second.filename = process_name;
      }
    } else {
      mergeProcessInfo(it->second, source_info);
    }
  }
}

/// @brief Сливает временную карту процессов `source` в `target`, двигая данные при возможности.
/// @param target Целевая карта процессов.
/// @param source Временная карта процессов.
void mergeProcessDataMaps(std::unordered_map<std::string, ProcessInfo>& target,
                          std::unordered_map<std::string, ProcessInfo>&& source) {
  target.reserve(target.size() + source.size());
  for (auto& [process_name, source_info] : source) {
    if (auto it = target.find(process_name); it == target.end()) {
      if (source_info.filename.empty()) {
        source_info.filename = process_name;
      }
      target.emplace(process_name, std::move(source_info));
    } else {
      mergeProcessInfo(it->second, std::move(source_info));
    }
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

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
