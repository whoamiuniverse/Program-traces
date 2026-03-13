#include <fstream>

#include <gtest/gtest.h>

#include "common/config_utils.hpp"
#include "infra/config/config.hpp"
#include "test_support.hpp"

TEST(ConfigUtilsTest, ReturnsVersionValueBeforeDefaults) {
  TestSupport::TempDir temp_dir("config_utils_version");
  const auto config_path = temp_dir.path() / "config.ini";

  std::ofstream file(config_path);
  file << "[VersionDefaults]\nPrefetchPath = Windows/Prefetch\n"
       << "[Windows10]\nPrefetchPath = Custom/Prefetch\n";
  file.close();

  Config config(config_path.string(), false, false);
  EXPECT_EQ(
      WindowsDiskAnalysis::ConfigUtils::getWithVersionFallback(
          config, "Windows10", "PrefetchPath"),
      "Custom/Prefetch");
  EXPECT_EQ(
      WindowsDiskAnalysis::ConfigUtils::getWithVersionFallback(
          config, "Windows7", "PrefetchPath"),
      "Windows/Prefetch");
}

TEST(ConfigUtilsTest, ReturnsSectionDefaultAndFallback) {
  TestSupport::TempDir temp_dir("config_utils_section");
  const auto config_path = temp_dir.path() / "config.ini";

  std::ofstream file(config_path);
  file << "[OSInfoRegistryPaths]\nDefault = Windows/System32/config/SOFTWARE\n"
       << "[OSInfoDefaults]\nRegistryPath = WINDOWS/system32/config/software\n";
  file.close();

  Config config(config_path.string(), false, false);
  EXPECT_EQ(
      WindowsDiskAnalysis::ConfigUtils::getWithSectionDefaultAndFallback(
          config, "OSInfoRegistryPaths", "Windows11", "OSInfoDefaults",
          "RegistryPath"),
      "Windows/System32/config/SOFTWARE");
}
