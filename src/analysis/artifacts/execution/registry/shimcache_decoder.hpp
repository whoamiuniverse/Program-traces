/// @file shimcache_decoder.hpp
/// @brief Format decoder for the binary AppCompatCache (ShimCache) registry value.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

/// @enum ShimCacheFormat
/// @brief Known binary formats of the Windows AppCompatCache (ShimCache) value.
enum class ShimCacheFormat {
  Unknown,    ///< Unrecognized or unsupported binary layout.
  XP32,       ///< Windows XP 32-bit format.
  Vista7_32,  ///< Windows Vista / 7 32-bit format.
  Vista7_64,  ///< Windows Vista / 7 64-bit format.
  Win8Plus,   ///< Windows 8 and later format.
};

/// @struct ShimCacheRecord
/// @brief Single decoded entry from the AppCompatCache binary blob.
struct ShimCacheRecord {
  std::string executable_path;  ///< Path to the executable file recorded in the cache.
  std::string timestamp;        ///< Last-modified timestamp of the executable at cache time.
  std::string details;          ///< Additional metadata (e.g., no-execute flag, format version).
  bool no_exec_flag = false;    ///< @c true if the entry has the "not executed" flag set (Win8+).
};

/// @brief Detects the ShimCache binary format from the raw data blob.
/// @param data Raw bytes of the @c AppCompatCache registry value.
/// @return Detected @c ShimCacheFormat, or @c ShimCacheFormat::Unknown if unrecognized.
ShimCacheFormat detectShimCacheFormat(const std::vector<uint8_t>& data);

/// @brief Parses ShimCache records from the raw AppCompatCache binary blob.
/// @param data           Raw bytes of the @c AppCompatCache registry value.
/// @param max_candidates Maximum number of records to return.
/// @return Vector of decoded @c ShimCacheRecord entries.
std::vector<ShimCacheRecord> parseShimCacheRecords(
    const std::vector<uint8_t>& data, std::size_t max_candidates);

}  // namespace WindowsDiskAnalysis
