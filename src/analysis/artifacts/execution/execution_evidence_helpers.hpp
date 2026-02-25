/// @file execution_evidence_helpers.hpp
/// @brief Декларации helper-функций для ExecutionEvidenceAnalyzer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "infra/config/config.hpp"
#include "parsers/registry/data_model/idata.hpp"
#include "parsers/registry/parser/iparser.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
#include <libesedb.h>
#endif

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

/// @brief Структурный кандидат записи ShimCache.
struct ShimCacheStructuredCandidate {
  std::string executable_path;
  std::string timestamp;
  std::string details;
};

/// @name Конфиг и пути
/// @{
/// @brief Читает значение из секции с fallback на ключ `Default`.
std::string getConfigValueWithSectionDefault(const Config& config,
                                             const std::string& section,
                                             const std::string& key);
/// @brief Ищет путь в ФС без учета регистра каждого компонента.
std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path);
/// @brief Нормализует путь к POSIX-разделителю (`/`).
std::string normalizePathSeparators(std::string path);
/// @brief Определяет путь в секции конфигурации по версии ОС.
/// @details При отсутствии точного совпадения использует ключ `Default`.
std::string findPathForOsVersion(const Config& config, const std::string& section,
                                 const std::string& os_version);
/// @brief Переводит лимит в MB в байты.
std::size_t toByteLimit(std::size_t mb);
/// @brief Собирает пути пользовательских hive (`NTUSER.DAT`).
std::vector<std::filesystem::path> collectUserHivePaths(
    const std::string& disk_root);
/// @brief Извлекает имя пользователя из пути к hive.
std::string extractUsernameFromHivePath(const std::filesystem::path& hive_path);
/// @}

/// @name Мутация `ProcessInfo`
/// @{
/// @brief Добавляет источник evidence без дублей.
void appendEvidenceSource(ProcessInfo& info, const std::string& source);
/// @brief Добавляет запись timeline без дублей.
void appendTimelineArtifact(ProcessInfo& info, std::string artifact);
/// @brief Добавляет tamper-флаг в вектор без дублей.
void appendTamperFlag(std::vector<std::string>& flags, std::string flag);
/// @brief Добавляет timestamp и обновляет first/last seen.
void addTimestamp(ProcessInfo& info, const std::string& timestamp);
/// @brief Формирует label для timeline-колонки.
std::string makeTimelineLabel(const std::string& source,
                              const std::string& timestamp,
                              const std::string& details);
/// @brief Гарантирует наличие bucket записи процесса в map.
ProcessInfo& ensureProcessInfo(std::map<std::string, ProcessInfo>& process_data,
                               const std::string& executable_path);
/// @brief Добавляет единицу execution evidence в `process_data`.
void addExecutionEvidence(std::map<std::string, ProcessInfo>& process_data,
                          const std::string& executable_path,
                          const std::string& source,
                          const std::string& timestamp,
                          const std::string& details);
/// @}

/// @name Реестр и control set
/// @{
/// @brief Декодирует ROT13 строку.
std::string decodeRot13(std::string value);
/// @brief Пытается извлечь индекс `ControlSetXXX` из registry value.
std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value);
/// @brief Определяет корень control set (`CurrentControlSet`/`ControlSetXXX`).
std::string resolveControlSetRoot(RegistryAnalysis::IRegistryParser& parser,
                                  const std::string& system_hive_path,
                                  const std::string& current_control_set_path);
/// @}

/// @name Парсинг строк и бинарных буферов
/// @{
/// @brief Собирает exe-кандидаты из начала файла.
void collectFileCandidates(const std::filesystem::path& file_path,
                           std::size_t max_bytes,
                           std::size_t max_candidates,
                           std::vector<std::string>& output);
/// @brief Парсит comma-separated список.
std::vector<std::string> parseListSetting(std::string raw);
/// @brief Извлекает значение XML-подобного тега `<tag>...</tag>`.
std::string extractTaggedValue(std::string value, const std::string& tag_name);
/// @brief Пытается извлечь executable из декорированного текста.
std::optional<std::string> tryExtractExecutableFromDecoratedText(
    std::string text);
/// @brief Извлекает читаемые ASCII/UTF16-строки из бинарного буфера.
std::vector<std::string> collectReadableStrings(const std::vector<uint8_t>& bytes,
                                                std::size_t min_length);
/// @brief Формирует относительный путь для timeline/details.
std::string makeRelativePathForDetails(const std::filesystem::path& base_root,
                                       const std::filesystem::path& file_path);
/// @brief Проверяет вхождение подстроки без учета регистра.
bool containsIgnoreCase(std::string value, const std::string& pattern);
/// @brief Проверяет наличие исполняемого расширения.
bool hasExecutionExtension(const std::string& candidate,
                           bool allow_com_extension);
/// @brief Эвристически определяет, похожа ли строка на executable path.
bool isLikelyExecutionPath(std::string candidate,
                           bool allow_com_extension = false);
/// @brief Проверяет похожесть строки на SID.
bool looksLikeSid(std::string value);
/// @brief Форматирует FILETIME в UTC в разумном диапазоне дат.
std::string formatReasonableFiletime(uint64_t filetime);
/// @brief Читает LE `uint16_t` из бинарного буфера.
uint16_t readLeUInt16Raw(const std::vector<uint8_t>& bytes, std::size_t offset);
/// @brief Декодирует UTF-16LE путь-кандидат из бинарного блока.
std::optional<std::string> decodeUtf16PathFromBytes(
    const std::vector<uint8_t>& bytes, std::size_t offset,
    std::size_t byte_size);
/// @brief Извлекает timestamp рядом со структурной записью ShimCache.
std::string extractShimCacheTimestamp(const std::vector<uint8_t>& bytes,
                                      std::size_t entry_offset,
                                      std::size_t path_offset,
                                      std::size_t path_size);
/// @brief Парсит структурные кандидаты из бинарного AppCompatCache.
std::vector<ShimCacheStructuredCandidate> parseShimCacheStructuredCandidates(
    const std::vector<uint8_t>& binary, std::size_t max_candidates);
/// @}

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
/// @name ESE helpers (libesedb)
/// @{
/// @brief Преобразует ошибку libesedb в строку.
std::string toLibesedbErrorMessage(libesedb_error_t* error);
/// @brief Нормализует UTF-8 значение из ESE (`\\0` removal + trim).
std::string sanitizeUtf8Value(std::string value);
/// @brief Читает UTF-8 имя колонки записи.
std::optional<std::string> readRecordColumnNameUtf8(libesedb_record_t* record,
                                                    int value_entry);
/// @brief Читает UTF-8 строковое значение колонки.
std::optional<std::string> readRecordValueUtf8(libesedb_record_t* record,
                                               int value_entry);
/// @brief Читает бинарное значение колонки.
std::optional<std::vector<uint8_t>> readRecordValueBinary(
    libesedb_record_t* record, int value_entry);
/// @brief Читает числовое значение колонки как `uint64_t`.
std::optional<uint64_t> readRecordValueU64(libesedb_record_t* record,
                                           int value_entry);
/// @brief Читает FILETIME значение колонки и форматирует в UTC.
std::optional<std::string> readRecordValueFiletimeString(
    libesedb_record_t* record, int value_entry);
/// @brief Читает UTF-8 имя таблицы ESE.
std::string getTableNameUtf8(libesedb_table_t* table);
/// @}
#endif

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
