/// @file execution_evidence_helpers.hpp
/// @brief Declarations of helper functions used by ExecutionEvidenceAnalyzer and its collectors.

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "infra/config/config.hpp"
#include "parsers/registry/data_model/idata.hpp"
#include "parsers/registry/parser/iparser.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
#include <libesedb.h>
#endif

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

// Constants used across collectors
extern const uint64_t kFiletimeUnixEpoch;    ///< FILETIME value corresponding to the Unix epoch (1970-01-01).
extern const uint64_t kMaxReasonableFiletime; ///< Upper bound for sanity-checking FILETIME values.

/// @brief Merges a source process data map into a target map.
/// @param target Destination map to merge into.
/// @param source Source map whose entries are merged into @p target.
void mergeProcessDataMaps(std::unordered_map<std::string, ProcessInfo>& target,
                          const std::unordered_map<std::string, ProcessInfo>& source);

/// @brief Merges a temporary source process data map into a target map, moving payloads where possible.
/// @param target Destination map to merge into.
/// @param source Temporary source map whose entries are moved/merged into @p target.
void mergeProcessDataMaps(std::unordered_map<std::string, ProcessInfo>& target,
                          std::unordered_map<std::string, ProcessInfo>&& source);

/// @brief Merges a source @c ProcessInfo into a target entry, deduplicating key fields.
/// @param target Destination @c ProcessInfo to merge into.
/// @param source Source @c ProcessInfo whose fields are merged.
void mergeProcessInfo(ProcessInfo& target, const ProcessInfo& source);

/// @brief Merges a temporary source @c ProcessInfo into a target entry, moving vectors/strings where possible.
/// @param target Destination @c ProcessInfo to merge into.
/// @param source Temporary source @c ProcessInfo whose fields are moved/merged.
void mergeProcessInfo(ProcessInfo& target, ProcessInfo&& source);

/// @brief Enriches a process entry with identity and privilege context extracted from a details string.
/// @param info    @c ProcessInfo to enrich.
/// @param details Raw details string potentially containing identity/privilege data.
void enrichProcessIdentityFromDetails(ProcessInfo& info,
                                      const std::string& details);

/// @struct ShimCacheStructuredCandidate
/// @brief Structured candidate record parsed from a binary AppCompatCache blob.
struct ShimCacheStructuredCandidate {
  std::string executable_path;  ///< Extracted executable file path.
  std::string timestamp;        ///< Timestamp associated with the cache entry.
  std::string details;          ///< Additional metadata (e.g., no-execute flag).
};

/// @name Configuration and path helpers
/// @{

/// @brief Reads a configuration value from a section with fallback to the @c Default key.
/// @param config  Application configuration object.
/// @param section INI section name.
/// @param key     Key to look up within the section.
/// @return Value for @p key in @p section, or the @c Default value if not found.
std::string getConfigValueWithSectionDefault(const Config& config,
                                             const std::string& section,
                                             const std::string& key);

/// @brief Resolves a filesystem path using case-insensitive component matching.
/// @param input_path Source path to resolve.
/// @return Resolved path on success, or @c std::nullopt if not found.
std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path);

/// @brief Normalizes all path separators in a string to POSIX forward slashes.
/// @param path Path string to normalize.
/// @return Normalized path string with @c '/' separators.
std::string normalizePathSeparators(std::string path);

/// @brief Finds a path value in a configuration section matching the OS version.
/// @details Falls back to the @c Default key when no exact version match exists.
/// @param config     Application configuration object.
/// @param section    INI section name.
/// @param os_version OS version string to match.
/// @return Resolved path string for the given OS version.
std::string findPathForOsVersion(const Config& config, const std::string& section,
                                 const std::string& os_version);

/// @brief Converts a megabyte limit to bytes.
/// @param mb Limit in megabytes.
/// @return Equivalent limit in bytes.
std::size_t toByteLimit(std::size_t mb);

/// @brief Collects paths to per-user NTUSER.DAT hive files.
/// @param disk_root Root path of the analyzed Windows partition.
/// @return Vector of resolved paths to NTUSER.DAT files.
std::vector<std::filesystem::path> collectUserHivePaths(
    const std::string& disk_root);

/// @brief Extracts the username from a path to an NTUSER.DAT hive.
/// @param hive_path Full path to the NTUSER.DAT file.
/// @return Username string extracted from the path.
std::string extractUsernameFromHivePath(const std::filesystem::path& hive_path);
/// @}

/// @name ProcessInfo mutation helpers
/// @{

/// @brief Appends an evidence source to a @c ProcessInfo entry without duplicates.
/// @param info   @c ProcessInfo to update.
/// @param source Evidence source label to append.
void appendEvidenceSource(ProcessInfo& info, const std::string& source);

/// @brief Appends a timeline artifact string to a @c ProcessInfo entry without duplicates.
/// @param info     @c ProcessInfo to update.
/// @param artifact Timeline artifact label to append.
void appendTimelineArtifact(ProcessInfo& info, std::string artifact);

/// @brief Appends a tamper flag to a vector without duplicates.
/// @param flags Vector of existing tamper flags.
/// @param flag  Tamper flag to append.
void appendTamperFlag(std::vector<std::string>& flags, std::string flag);

/// @brief Records a timestamp in a @c ProcessInfo entry and updates first/last-seen fields.
/// @param info      @c ProcessInfo to update.
/// @param timestamp Timestamp string to record.
void addTimestamp(ProcessInfo& info, const std::string& timestamp);

/// @brief Formats a timeline column label from source, timestamp, and details.
/// @param source    Evidence source label.
/// @param timestamp Timestamp string.
/// @param details   Additional detail string.
/// @return Formatted timeline label.
std::string makeTimelineLabel(const std::string& source,
                              const std::string& timestamp,
                              const std::string& details);

/// @brief Ensures a bucket for the given executable path exists in the process map.
/// @param process_data   Map of processes to search or insert into.
/// @param executable_path Canonical executable path used as the map key.
/// @return Reference to the existing or newly created @c ProcessInfo entry.
ProcessInfo& ensureProcessInfo(std::unordered_map<std::string, ProcessInfo>& process_data,
                               const std::string& executable_path);

/// @brief Adds a single execution evidence record to the process map.
/// @param process_data    Map of processes to update.
/// @param executable_path Canonical executable path.
/// @param source          Evidence source label.
/// @param timestamp       Timestamp string.
/// @param details         Additional detail string.
void addExecutionEvidence(std::unordered_map<std::string, ProcessInfo>& process_data,
                          const std::string& executable_path,
                          const std::string& source,
                          const std::string& timestamp,
                          const std::string& details);
/// @}

/// @name Registry and control set helpers
/// @{

/// @brief Decodes a ROT-13 encoded string.
/// @param value ROT-13 encoded input string.
/// @return Decoded string.
std::string decodeRot13(std::string value);

/// @brief Attempts to extract a ControlSet index from a registry value.
/// @param value Registry data value to parse.
/// @return Control set index on success, or @c std::nullopt.
std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value);

/// @brief Resolves the active control set root path in the SYSTEM hive.
/// @param parser                   Registry parser instance.
/// @param system_hive_path         Path to the SYSTEM hive file.
/// @param current_control_set_path Default path to try first (e.g., @c "CurrentControlSet").
/// @return Resolved control set root path string.
std::string resolveControlSetRoot(RegistryAnalysis::IRegistryParser& parser,
                                  const std::string& system_hive_path,
                                  const std::string& current_control_set_path);
/// @}

/// @name String and binary buffer parsing helpers
/// @{

/// @brief Scans the beginning of a file and collects executable path candidates.
/// @param file_path      Path to the file to scan.
/// @param max_bytes      Maximum number of bytes to read.
/// @param max_candidates Upper bound on the number of collected candidates.
/// @param output         Output vector to append found candidates to.
void collectFileCandidates(const std::filesystem::path& file_path,
                           std::size_t max_bytes,
                           std::size_t max_candidates,
                           std::vector<std::string>& output);

/// @brief Parses a comma-separated setting string into a vector of strings.
/// @param raw Raw comma-separated string.
/// @return Vector of trimmed string tokens.
std::vector<std::string> parseListSetting(std::string raw);

/// @brief Extracts the value between @c <tag>...</tag> XML-like delimiters.
/// @param value     String potentially containing the tagged value.
/// @param tag_name  Name of the tag (without angle brackets).
/// @return Extracted inner content, or an empty string if not found.
std::string extractTaggedValue(std::string value, const std::string& tag_name);

/// @brief Attempts to extract an executable path from a decorated text string.
/// @param text Decorated text that may contain an executable path.
/// @return Extracted executable path, or @c std::nullopt if extraction failed.
std::optional<std::string> tryExtractExecutableFromDecoratedText(
    std::string text);

/// @brief Extracts readable ASCII and UTF-16LE strings from a binary buffer.
/// @param bytes      Binary buffer to scan.
/// @param min_length Minimum string length to include in results.
/// @return Vector of extracted readable strings.
std::vector<std::string> collectReadableStrings(const std::vector<uint8_t>& bytes,
                                                std::size_t min_length);

/// @brief Formats a relative path string suitable for timeline or details columns.
/// @param base_root Root path used to compute the relative path.
/// @param file_path Absolute file path to make relative.
/// @return Relative path string.
std::string makeRelativePathForDetails(const std::filesystem::path& base_root,
                                       const std::filesystem::path& file_path);

/// @brief Checks whether a string contains a substring in a case-insensitive manner.
/// @param value   String to search within.
/// @param pattern Substring to search for (case-insensitive).
/// @return @c true if @p value contains @p pattern ignoring case.
bool containsIgnoreCase(std::string value, const std::string& pattern);

/// @brief Checks whether a string has a recognized executable file extension.
/// @param candidate          Candidate string to check.
/// @param allow_com_extension Whether to treat @c .com as a valid executable extension.
/// @return @c true if the candidate has a recognized execution extension.
bool hasExecutionExtension(const std::string& candidate,
                           bool allow_com_extension);

/// @brief Heuristically determines whether a string resembles an executable path.
/// @param candidate          Candidate string to evaluate.
/// @param allow_com_extension Whether @c .com is treated as a valid extension.
/// @return @c true if the candidate looks like an executable path.
bool isLikelyExecutionPath(std::string candidate,
                           bool allow_com_extension = false);

/// @brief Checks whether a string resembles a Windows Security Identifier (SID).
/// @param value String to test.
/// @return @c true if the string looks like a SID.
bool looksLikeSid(std::string value);

/// @brief Extracts SID candidate strings from a text line.
/// @param line Text line to scan.
/// @return Vector of SID-like substrings found in @p line.
std::vector<std::string> extractSidCandidatesFromLine(const std::string& line);

/// @brief Formats a Windows FILETIME value as a UTC timestamp string if within a reasonable range.
/// @param filetime 64-bit FILETIME value.
/// @return Formatted UTC timestamp string, or an empty string if out of range.
std::string formatReasonableFiletime(uint64_t filetime);

/// @brief Normalizes a raw firewall rule direction string to a canonical label.
/// @param raw_direction Raw direction string from the registry.
/// @return Normalized direction string (e.g., @c "Inbound" or @c "Outbound").
std::string normalizeFirewallDirection(std::string raw_direction);

/// @brief Normalizes a raw firewall rule action string to a canonical label.
/// @param raw_action Raw action string from the registry.
/// @return Normalized action string (e.g., @c "Allow" or @c "Block").
std::string normalizeFirewallAction(std::string raw_action);

/// @brief Normalizes a raw firewall rule protocol string to a canonical label.
/// @param raw_protocol Raw protocol string from the registry.
/// @return Normalized protocol string (e.g., @c "TCP", @c "UDP", @c "Any").
std::string normalizeFirewallProtocol(std::string raw_protocol);

/// @brief Parses a @c SYSTEMTIME structure from a registry binary blob.
/// @param binary Binary data blob containing the @c SYSTEMTIME structure.
/// @return Formatted UTC timestamp string on success, or @c std::nullopt on failure.
std::optional<std::string> parseRegistrySystemTime(
    const std::vector<uint8_t>& binary);

/// @brief Normalizes a raw NetworkList profile category value to a canonical label.
/// @param raw_category Raw category string or integer from the registry.
/// @return Normalized category string (e.g., @c "Public", @c "Private", @c "Domain").
std::string normalizeNetworkProfileCategory(std::string raw_category);

/// @brief Parses a firewall rule data string in @c "k=v|..." format into a key-value map.
/// @param raw_rule Raw firewall rule string from the registry.
/// @return Map of parsed key-value pairs.
std::unordered_map<std::string, std::string> parseFirewallRuleData(
    std::string raw_rule);

/// @brief Returns the synthetic process map key used for global network context entries.
/// @return Synthetic process key string.
std::string networkContextProcessKey();

/// @brief Reads a little-endian @c uint16_t from a binary buffer at a given offset.
/// @param bytes  Binary buffer.
/// @param offset Byte offset to read from.
/// @return The @c uint16_t value read from the buffer.
uint16_t readLeUInt16Raw(const std::vector<uint8_t>& bytes, std::size_t offset);

/// @brief Decodes a UTF-16LE path candidate from a binary buffer at a given offset.
/// @param bytes     Binary buffer.
/// @param offset    Byte offset of the first UTF-16LE code unit.
/// @param byte_size Number of bytes to decode.
/// @return Decoded UTF-8 path string on success, or @c std::nullopt on failure.
std::optional<std::string> decodeUtf16PathFromBytes(
    const std::vector<uint8_t>& bytes, std::size_t offset,
    std::size_t byte_size);

/// @brief Extracts the timestamp nearest to a ShimCache entry in a binary blob.
/// @param bytes        Binary buffer containing the AppCompatCache data.
/// @param entry_offset Byte offset of the cache entry header.
/// @param path_offset  Byte offset of the executable path within the entry.
/// @param path_size    Size of the executable path in bytes.
/// @return Formatted timestamp string, or an empty string if not found.
std::string extractShimCacheTimestamp(const std::vector<uint8_t>& bytes,
                                      std::size_t entry_offset,
                                      std::size_t path_offset,
                                      std::size_t path_size);

/// @brief Parses structured ShimCache candidates from a binary AppCompatCache blob.
/// @param binary         Binary AppCompatCache blob.
/// @param max_candidates Maximum number of candidates to return.
/// @return Vector of structured ShimCache candidate records.
std::vector<ShimCacheStructuredCandidate> parseShimCacheStructuredCandidates(
    const std::vector<uint8_t>& binary, std::size_t max_candidates);
/// @}

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB
/// @name ESE database helpers (requires libesedb)
/// @{

/// @brief Converts a libesedb error object to a descriptive string.
/// @param error Pointer to the libesedb error object.
/// @return Human-readable error message string.
std::string toLibesedbErrorMessage(libesedb_error_t* error);

/// @brief Sanitizes a UTF-8 string value from ESE by removing null bytes and trimming whitespace.
/// @param value Raw UTF-8 string from libesedb.
/// @return Sanitized string.
std::string sanitizeUtf8Value(std::string value);

/// @brief Reads the UTF-8 column name from an ESE record entry.
/// @param record      Pointer to the libesedb record.
/// @param value_entry Column (value entry) index.
/// @return Column name string on success, or @c std::nullopt on failure.
std::optional<std::string> readRecordColumnNameUtf8(libesedb_record_t* record,
                                                    int value_entry);

/// @brief Reads a UTF-8 string value from an ESE record column.
/// @param record      Pointer to the libesedb record.
/// @param value_entry Column (value entry) index.
/// @return Column value string on success, or @c std::nullopt on failure.
std::optional<std::string> readRecordValueUtf8(libesedb_record_t* record,
                                               int value_entry);

/// @brief Reads a binary value from an ESE record column.
/// @param record      Pointer to the libesedb record.
/// @param value_entry Column (value entry) index.
/// @return Binary data vector on success, or @c std::nullopt on failure.
std::optional<std::vector<uint8_t>> readRecordValueBinary(
    libesedb_record_t* record, int value_entry);

/// @brief Reads a numeric value from an ESE record column as @c uint64_t.
/// @param record      Pointer to the libesedb record.
/// @param value_entry Column (value entry) index.
/// @return Numeric value on success, or @c std::nullopt on failure.
std::optional<uint64_t> readRecordValueU64(libesedb_record_t* record,
                                           int value_entry);

/// @brief Reads a FILETIME value from an ESE record column and formats it as a UTC string.
/// @param record      Pointer to the libesedb record.
/// @param value_entry Column (value entry) index.
/// @return Formatted UTC timestamp string on success, or @c std::nullopt on failure.
std::optional<std::string> readRecordValueFiletimeString(
    libesedb_record_t* record, int value_entry);

/// @brief Reads the UTF-8 name of an ESE table.
/// @param table Pointer to the libesedb table.
/// @return Table name string, or an empty string on failure.
std::string getTableNameUtf8(libesedb_table_t* table);
/// @}
#endif

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
