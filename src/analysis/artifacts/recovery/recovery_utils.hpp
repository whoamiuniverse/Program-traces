/// @file recovery_utils.hpp
/// @brief Shared utility functions for recovery analyzers (USN/VSS/Hiber/NTFS/Registry/Signature/TSK).

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis::RecoveryUtils {

/// @brief Resolves a filesystem path using case-insensitive component matching.
/// @param input_path Source path to resolve.
/// @return Resolved path on success, or @c std::nullopt if not found.
[[nodiscard]] std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path);

/// @brief Converts a megabyte limit to bytes, enforcing a minimum of 1 MB.
/// @param megabytes Limit in megabytes.
/// @return Limit in bytes (at least 1 MB).
[[nodiscard]] std::size_t toByteLimit(std::size_t megabytes);

/// @brief Performs a binary fallback scan of a file for executable path candidates.
/// @param file_path        Path to the source file to scan.
/// @param source           Logical source label (e.g., @c "USN", @c "VSS", @c "Hiber").
/// @param recovered_from   Recovery marker label (e.g., @c "USN.binary").
/// @param max_bytes        Maximum number of bytes to read from the start of the file.
/// @param max_candidates   Upper bound on the number of extracted candidates.
/// @return Vector of @c RecoveryEvidence records extracted from the binary scan.
[[nodiscard]] std::vector<RecoveryEvidence> scanRecoveryFileBinary(
    const std::filesystem::path& file_path, const std::string& source,
    const std::string& recovered_from, std::size_t max_bytes,
    std::size_t max_candidates);

/// @brief Performs a signature/string recovery scan on an already-loaded memory buffer.
/// @param buffer          Contents of the block to scan.
/// @param source          Logical source label (e.g., @c "USN", @c "VSS", @c "Hiber").
/// @param recovered_from  Recovery marker label (e.g., @c "Hiber.native").
/// @param container_label Label of the containing artifact (e.g., file name).
/// @param timestamp       Timestamp associated with the source.
/// @param max_candidates  Upper bound on the number of returned candidates.
/// @param base_offset     Byte offset of the buffer within the containing artifact.
/// @param chunk_source    Chunk origin descriptor (e.g., @c "file_head", @c "mft_record").
/// @param container_size  Full size of the analyzed container used to classify the chunk
///                        as @c head / @c middle / @c tail. If @c 0, the buffer size is used.
/// @return Vector of @c RecoveryEvidence records extracted from the buffer.
[[nodiscard]] std::vector<RecoveryEvidence> scanRecoveryBufferBinary(
    const std::vector<uint8_t>& buffer, const std::string& source,
    const std::string& recovered_from, const std::string& container_label,
    const std::string& timestamp, std::size_t max_candidates,
    std::uint64_t base_offset = 0,
    const std::string& chunk_source = "buffer",
    std::size_t container_size = 0);

/// @brief Builds a deduplication key for a recovery evidence record.
/// @param evidence The evidence record to key.
/// @return Normalized string key suitable for use in an unordered set.
[[nodiscard]] std::string buildEvidenceDedupKey(
    const RecoveryEvidence& evidence);

/// @brief Appends evidence records to a target vector, skipping duplicates.
/// @param target     Destination vector of evidence records.
/// @param source     Source vector of evidence records (will be consumed via move).
/// @param dedup_keys Set of deduplication keys tracking already-added records.
void appendUniqueEvidence(std::vector<RecoveryEvidence>& target,
                          std::vector<RecoveryEvidence>& source,
                          std::unordered_set<std::string>& dedup_keys);

}  // namespace WindowsDiskAnalysis::RecoveryUtils
