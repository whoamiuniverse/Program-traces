#include <filesystem>

#include <gtest/gtest.h>

#include "parsers/prefetch/data_model/prefetch_versions.hpp"
#include "parsers/prefetch/parser/parser.hpp"

TEST(PrefetchParserTest, ParsesRealFixtureHeader) {
  const auto fixture_path = std::filesystem::path(PROGRAM_TRACES_FIXTURES_DIR) /
                            "prefetch" / "CMD.EXE-087B4001.pf";

  PrefetchAnalysis::PrefetchParser parser;
  const auto parsed = parser.parse(fixture_path.string());

  ASSERT_NE(parsed, nullptr);
  EXPECT_EQ(parsed->getExecutableName(), "CMD.EXE");
  EXPECT_EQ(parsed->getFormatVersion(), 17U);
  EXPECT_EQ(parsed->getPrefetchHash(), 0x087B4001U);
  EXPECT_EQ(parsed->getRunCount(), 2U);
  ASSERT_EQ(parsed->getRunTimes().size(), 1U);
  EXPECT_EQ(parsed->getLastRunTime(), 1362910309U);
  EXPECT_TRUE(parsed->isVersionSupported(
      PrefetchAnalysis::PrefetchFormatVersion::WIN_XP_SP2));
}

TEST(PrefetchParserTest, MapsKnownVersionsToEnum) {
  EXPECT_EQ(PrefetchAnalysis::toVersionEnum(17U),
            PrefetchAnalysis::PrefetchFormatVersion::WIN_XP_SP2);
  EXPECT_EQ(PrefetchAnalysis::toVersionEnum(23U),
            PrefetchAnalysis::PrefetchFormatVersion::WIN_VISTA_7);
  EXPECT_EQ(PrefetchAnalysis::toVersionEnum(26U),
            PrefetchAnalysis::PrefetchFormatVersion::WIN8_10_PRE_RS1);
  EXPECT_EQ(PrefetchAnalysis::toVersionEnum(30U),
            PrefetchAnalysis::PrefetchFormatVersion::WIN10_RS1_PLUS);
}
