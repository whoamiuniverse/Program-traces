#include <filesystem>

#include <gtest/gtest.h>

TEST(PipelineIntegrationTest, Win10FixturePlaceholder) {
  const std::filesystem::path fixture_dir =
      std::filesystem::path(PROGRAM_TRACES_FIXTURES_DIR) / "pipeline" / "win10";
  if (!std::filesystem::exists(fixture_dir)) {
    GTEST_SKIP() << "Win10 integration fixture is not available in tests/fixtures.";
  }

  SUCCEED();
}
