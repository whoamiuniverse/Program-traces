#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/execution/registry/shimcache_decoder.hpp"

namespace {

void writeLe32(std::vector<uint8_t>& data, const std::size_t offset,
               const uint32_t value) {
  data[offset] = static_cast<uint8_t>(value & 0xFF);
  data[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  data[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
  data[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void writeUtf16(std::vector<uint8_t>& data, const std::size_t offset,
                const std::string& value) {
  for (std::size_t index = 0; index < value.size(); ++index) {
    data[offset + index * 2] = static_cast<uint8_t>(value[index]);
    data[offset + index * 2 + 1] = 0;
  }
  data[offset + value.size() * 2] = 0;
  data[offset + value.size() * 2 + 1] = 0;
}

std::vector<uint8_t> buildXpShimcacheSample() {
  std::vector<uint8_t> data(8 + 552, 0);
  writeLe32(data, 0, 0x900EF489U);
  writeLe32(data, 4, 1);
  writeUtf16(data, 8, R"(C:\Windows\System32\calc.exe)");
  writeLe32(data, 8 + 528, 1);
  return data;
}

std::vector<uint8_t> buildVistaShimcacheSample() {
  std::vector<uint8_t> data(8 + 96, 0);
  writeLe32(data, 0, 0xBADC0FFEU);
  writeLe32(data, 4, 1);
  writeLe32(data, 8, 96);
  writeUtf16(data, 16, R"(C:\Program Files\App\app.exe)");
  writeLe32(data, 8 + 96 - 4, 1);
  return data;
}

std::vector<uint8_t> buildWin8ShimcacheSample() {
  std::vector<uint8_t> data(64, 0);
  writeLe32(data, 0, 0x00000080U);
  data[8] = '1';
  data[9] = '0';
  data[10] = 't';
  data[11] = 's';
  writeUtf16(data, 12, R"(C:\Windows\explorer.exe)");
  return data;
}

}  // namespace

TEST(ShimCacheDecoderTest, DetectsAndParsesKnownFormats) {
  const auto xp = buildXpShimcacheSample();
  const auto vista = buildVistaShimcacheSample();
  const auto win8 = buildWin8ShimcacheSample();

  EXPECT_EQ(WindowsDiskAnalysis::detectShimCacheFormat(xp),
            WindowsDiskAnalysis::ShimCacheFormat::XP32);
  EXPECT_EQ(WindowsDiskAnalysis::detectShimCacheFormat(vista),
            WindowsDiskAnalysis::ShimCacheFormat::Vista7_32);
  EXPECT_EQ(WindowsDiskAnalysis::detectShimCacheFormat(win8),
            WindowsDiskAnalysis::ShimCacheFormat::Win8Plus);

  const auto xp_records = WindowsDiskAnalysis::parseShimCacheRecords(xp, 8);
  const auto vista_records =
      WindowsDiskAnalysis::parseShimCacheRecords(vista, 8);
  const auto win8_records =
      WindowsDiskAnalysis::parseShimCacheRecords(win8, 8);

  ASSERT_EQ(xp_records.size(), 1U);
  ASSERT_EQ(vista_records.size(), 1U);
  ASSERT_EQ(win8_records.size(), 1U);

  EXPECT_EQ(xp_records.front().executable_path,
            R"(C:\Windows\System32\calc.exe)");
  EXPECT_EQ(vista_records.front().executable_path,
            R"(C:\Program Files\App\app.exe)");
  EXPECT_EQ(win8_records.front().executable_path,
            R"(C:\Windows\explorer.exe)");
  EXPECT_TRUE(win8_records.front().no_exec_flag);
}
