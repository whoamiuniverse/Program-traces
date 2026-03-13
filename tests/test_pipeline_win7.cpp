#include <filesystem>

#include <gtest/gtest.h>

TEST(PipelineIntegrationTest, Win7FixturePlaceholder) {
  const std::filesystem::path fixture_dir =
      std::filesystem::path(PROGRAM_TRACES_FIXTURES_DIR) / "pipeline" / "win7";
  if (!std::filesystem::exists(fixture_dir)) {
    GTEST_SKIP() << "Win7 integration fixture is not available in tests/fixtures.";
  }

  SUCCEED();
}
