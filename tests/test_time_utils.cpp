#include <gtest/gtest.h>

#include "common/time_utils.hpp"

TEST(TimeUtilsTest, ConvertsEpochAndZeroFiletime) {
  EXPECT_EQ(filetimeToString(0), "N/A");
  EXPECT_EQ(filetimeToString(116444736000000000ULL), "1970-01-01 00:00:00");
}

TEST(TimeUtilsTest, ConvertsFiletimeToUnixAndUtcString) {
  const uint64_t filetime = 132537600000000000ULL;  // 2020-12-30 00:00:00 UTC
  EXPECT_EQ(filetimeToUnixTime(filetime), 1609286400);
  EXPECT_EQ(unixTimeToString(1609286400), "2020-12-30 00:00:00");
}
