#include <algorithm>
#include <filesystem>
#include <vector>

#include <gtest/gtest.h>

#include "parsers/registry/enums/value_type.hpp"
#include "parsers/registry/parser/parser.hpp"

TEST(RegistryParserTest, ReadsStringBinaryAndDwordValuesFromRealHive) {
  const auto hive_path = std::filesystem::path(PROGRAM_TRACES_FIXTURES_DIR) /
                         "registry" / "NTUSER.DAT";

  RegistryAnalysis::RegistryParser parser;

  const auto root_subkeys = parser.listSubkeys(hive_path.string(), "");
  EXPECT_NE(std::find(root_subkeys.begin(), root_subkeys.end(), "Software"),
            root_subkeys.end());
  EXPECT_NE(std::find(root_subkeys.begin(), root_subkeys.end(), "Control Panel"),
            root_subkeys.end());

  const auto wallpaper = parser.getSpecificValue(
      hive_path.string(), "Control Panel/Desktop/Wallpaper");
  ASSERT_NE(wallpaper, nullptr);
  EXPECT_EQ(wallpaper->getType(), RegistryAnalysis::RegistryValueType::REG_SZ);
  EXPECT_EQ(wallpaper->getAsString(),
            R"(C:\Windows\Web\Wallpaper\Windows\img0.jpg)");

  const auto smoothing_type = parser.getSpecificValue(
      hive_path.string(), "Control Panel/Desktop/FontSmoothingType");
  ASSERT_NE(smoothing_type, nullptr);
  EXPECT_EQ(smoothing_type->getType(),
            RegistryAnalysis::RegistryValueType::REG_DWORD);
  EXPECT_EQ(smoothing_type->getAsDword(), 2U);
  EXPECT_EQ(smoothing_type->getDataAsString(), "2");

  const auto preferences_mask = parser.getSpecificValue(
      hive_path.string(), "Control Panel/Desktop/UserPreferencesMask");
  ASSERT_NE(preferences_mask, nullptr);
  EXPECT_EQ(preferences_mask->getType(),
            RegistryAnalysis::RegistryValueType::REG_BINARY);
  const std::vector<uint8_t> expected_mask = {0x9E, 0x1E, 0x07, 0x80,
                                              0x12, 0x00, 0x00, 0x00};
  EXPECT_EQ(preferences_mask->getAsBinary(), expected_mask);

  const auto desktop_values =
      parser.getKeyValues(hive_path.string(), "Control Panel/Desktop");
  EXPECT_FALSE(desktop_values.empty());
}
