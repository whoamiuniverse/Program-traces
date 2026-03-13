/// @file shimcache_decoder.hpp
/// @brief Форматный декодер бинарного AppCompatCache (ShimCache).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace WindowsDiskAnalysis {

enum class ShimCacheFormat {
  Unknown,
  XP32,
  Vista7_32,
  Vista7_64,
  Win8Plus,
};

struct ShimCacheRecord {
  std::string executable_path;
  std::string timestamp;
  std::string details;
  bool no_exec_flag = false;
};

ShimCacheFormat detectShimCacheFormat(const std::vector<uint8_t>& data);

std::vector<ShimCacheRecord> parseShimCacheRecords(
    const std::vector<uint8_t>& data, std::size_t max_candidates);

}  // namespace WindowsDiskAnalysis
