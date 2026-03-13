#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "parsers/lnk/lnk_parser.hpp"

namespace {

constexpr uint8_t kClsid[16] = {0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x46};

void writeLe16(std::vector<uint8_t>& data, const std::size_t offset,
               const uint16_t value) {
  data[offset] = static_cast<uint8_t>(value & 0xFF);
  data[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

void writeLe32(std::vector<uint8_t>& data, const std::size_t offset,
               const uint32_t value) {
  data[offset] = static_cast<uint8_t>(value & 0xFF);
  data[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  data[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
  data[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void writeLe64(std::vector<uint8_t>& data, const std::size_t offset,
               const uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    data[offset + index] = static_cast<uint8_t>((value >> (index * 8)) & 0xFF);
  }
}

void appendAsciiZ(std::vector<uint8_t>& data, const std::string& value) {
  data.insert(data.end(), value.begin(), value.end());
  data.push_back(0);
}

void appendUnicodeString(std::vector<uint8_t>& data, const std::string& value) {
  const std::size_t start = data.size();
  data.resize(start + 2 + value.size() * 2, 0);
  writeLe16(data, start, static_cast<uint16_t>(value.size()));
  std::size_t offset = start + 2;
  for (std::size_t index = 0; index < value.size(); ++index) {
    data[offset + index * 2] = static_cast<uint8_t>(value[index]);
    data[offset + index * 2 + 1] = 0;
  }
}

std::vector<uint8_t> buildLnkSample() {
  std::vector<uint8_t> data(0x4C, 0);
  writeLe32(data, 0, 0x4C);
  std::copy(std::begin(kClsid), std::end(kClsid), data.begin() + 4);

  constexpr uint32_t flags =
      0x00000002U | 0x00000008U | 0x00000010U | 0x00000020U | 0x00000080U;
  writeLe32(data, 0x14, flags);
  writeLe64(data, 0x1C, 132223104000000000ULL);  // 2020-01-01 00:00:00 UTC
  writeLe64(data, 0x24, 132223104000000000ULL);
  writeLe64(data, 0x2C, 132223104000000000ULL);

  const std::size_t link_info_offset = data.size();
  const std::string local_base = R"(C:\Program Files\Test App)";
  const std::string suffix = "app.exe";
  const uint32_t link_info_size =
      static_cast<uint32_t>(0x1C + local_base.size() + 1 + suffix.size() + 1);
  data.resize(data.size() + link_info_size, 0);

  writeLe32(data, link_info_offset + 0, link_info_size);
  writeLe32(data, link_info_offset + 4, 0x1C);
  writeLe32(data, link_info_offset + 8, 1);
  writeLe32(data, link_info_offset + 16, 0x1C);
  writeLe32(data, link_info_offset + 24,
            0x1C + static_cast<uint32_t>(local_base.size()) + 1);

  std::size_t cursor = link_info_offset + 0x1C;
  for (const char ch : local_base) {
    data[cursor++] = static_cast<uint8_t>(ch);
  }
  data[cursor++] = 0;
  for (const char ch : suffix) {
    data[cursor++] = static_cast<uint8_t>(ch);
  }
  data[cursor] = 0;

  appendUnicodeString(data, R"(Test App\app.exe)");
  appendUnicodeString(data, R"(C:\Program Files\Test App)");
  appendUnicodeString(data, "--flag");
  return data;
}

}  // namespace

TEST(LnkParserTest, ParsesTargetPathAndHeaderTimes) {
  const auto info = WindowsDiskAnalysis::parseLnkBytes(buildLnkSample());
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->target_path, R"(C:\Program Files\Test App\app.exe)");
  EXPECT_EQ(info->relative_path, R"(Test App\app.exe)");
  EXPECT_EQ(info->working_dir, R"(C:\Program Files\Test App)");
  EXPECT_EQ(info->arguments, "--flag");
  EXPECT_EQ(info->write_time, "2020-01-01 00:00:00");
}

TEST(LnkParserTest, ParsesRealFixtureFile) {
  const auto fixture_path =
      std::filesystem::path(PROGRAM_TRACES_FIXTURES_DIR) / "lnk" / "example.lnk";
  const auto info = WindowsDiskAnalysis::parseLnkFile(fixture_path.string());
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->target_path,
            R"(.\migwiz\migwiz.exe\@%windir%\system32\migwiz\wet.dll,-590)");
  EXPECT_EQ(info->relative_path,
            R"(@%windir%\system32\migwiz\wet.dll,-590)");
  EXPECT_EQ(info->working_dir, R"(.\migwiz\migwiz.exe)");
  EXPECT_EQ(info->creation_time, "2009-07-13 23:29:02");
  EXPECT_EQ(info->access_time, "2009-07-13 23:29:02");
  EXPECT_EQ(info->write_time, "2009-07-14 01:39:18");
}
