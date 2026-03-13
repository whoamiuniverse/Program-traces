#include <fstream>
#include <memory>

#include <gtest/gtest.h>

#include "analysis/artifacts/amcache/amcache_analyzer.hpp"
#include "parsers/registry/parser/iparser.hpp"
#include "test_support.hpp"

namespace {

class StubRegistryParser final : public RegistryAnalysis::IRegistryParser {
 public:
  std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> getKeyValues(
      const std::string&, const std::string&) override {
    return {};
  }

  std::unique_ptr<RegistryAnalysis::IRegistryData> getSpecificValue(
      const std::string&, const std::string&) override {
    return nullptr;
  }

  std::vector<std::string> listSubkeys(const std::string&,
                                       const std::string&) override {
    return {};
  }
};

}  // namespace

TEST(AmcacheAnalyzerTest, FallsBackToRecentFileCacheForWindows7) {
  TestSupport::TempDir temp_dir("amcache");
  const auto ini_path = temp_dir.path() / "config.ini";
  const auto bcf_path =
      temp_dir.path() / "Windows" / "AppCompat" / "Programs" /
      "RecentFileCache.bcf";

  std::filesystem::create_directories(bcf_path.parent_path());
  {
    std::ofstream bcf(bcf_path);
    bcf << "# comment\n"
        << R"(C:\Program Files\App\app.exe)" << "\n"
        << R"(C:\Windows\System32\calc.exe)" << "\n";
  }

  {
    std::ofstream ini(ini_path);
    ini << "[VersionDefaults]\nAmcachePath = \nAmcacheKeys = \n"
        << "[Windows7]\n"
        << "AmcachePath = \n"
        << "AmcacheKeys = \n"
        << "RecentFileCachePath = Windows/AppCompat/Programs/RecentFileCache.bcf\n";
  }

  WindowsDiskAnalysis::AmcacheAnalyzer analyzer(
      std::make_unique<StubRegistryParser>(), "Windows7", ini_path.string());

  const auto entries = analyzer.collect(temp_dir.path().string());
  ASSERT_EQ(entries.size(), 2U);
  EXPECT_EQ(entries.front().source, "Amcache(BCF)");
  EXPECT_EQ(entries.front().name, "app.exe");
  EXPECT_EQ(entries.back().file_path, R"(C:/Windows/System32/calc.exe)");
}
