/// @file test_artifact_paths_by_os.cpp
/// @brief Проверка выбора путей артефактов для Windows 7/8/10/11.

#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/config_utils.hpp"
#include "infra/config/config.hpp"
#include "test_support.hpp"

namespace {

/// @brief Создаёт тестовый INI с матрицей путей для Win7/8/10/11.
/// @param dir Временный каталог теста.
/// @return Абсолютный путь к созданному файлу конфигурации.
std::string writePathMatrixConfig(const TestSupport::TempDir& dir) {
  const auto config_path = dir.path() / "artifact_paths.ini";
  std::ofstream file(config_path);
  file
      << "[VersionDefaults]\n"
      << "PrefetchPath = Windows/Prefetch\n"
      << "EventLogs = Windows/System32/winevt/Logs/\n"
      << "AmcachePath = Windows/appcompat/Programs/Amcache.hve\n"
      << "RecentFileCachePath =\n"
      << "[Windows7]\n"
      << "PrefetchPath = WINDOWS\\Prefetch\n"
      << "EventLogs = WINDOWS\\System32\\winevt\\Logs\\\n"
      << "AmcachePath =\n"
      << "RecentFileCachePath = WINDOWS\\AppCompat\\Programs\\RecentFileCache.bcf\n"
      << "[Windows8]\n"
      << "PrefetchPath = Windows\\Prefetch\n"
      << "EventLogs = Windows\\System32\\winevt\\Logs\\\n"
      << "AmcachePath = Windows\\appcompat\\Programs\\Amcache.hve\n"
      << "[Windows10]\n"
      << "PrefetchPath = Windows\\Prefetch\n"
      << "EventLogs = Windows\\System32\\winevt\\Logs\\\n"
      << "AmcachePath = Windows\\appcompat\\Programs\\Amcache.hve\n"
      << "[Windows11]\n"
      << "PrefetchPath = Windows\\Prefetch\n"
      << "EventLogs = Windows\\System32\\winevt\\Logs\\\n"
      << "AmcachePath = Windows\\appcompat\\Programs\\Amcache.hve\n"
      << "[OSInfoRegistryPaths]\n"
      << "Default = Windows/System32/config/SOFTWARE\n"
      << "Windows7 = WINDOWS\\system32\\config\\software\n"
      << "Windows8 = Windows/System32/config/SOFTWARE\n"
      << "Windows10 = Windows/System32/config/SOFTWARE\n"
      << "Windows11 = Windows/System32/config/SOFTWARE\n"
      << "[OSInfoSystemRegistryPaths]\n"
      << "Default = Windows/System32/config/SYSTEM\n"
      << "Windows7 = WINDOWS\\system32\\config\\system\n"
      << "Windows8 = Windows/System32/config/SYSTEM\n"
      << "Windows10 = Windows/System32/config/SYSTEM\n"
      << "Windows11 = Windows/System32/config/SYSTEM\n";
  file.close();
  return config_path.string();
}

}  // namespace

TEST(ArtifactPathsByOsTest, VersionFallbackSelectsExpectedArtifactPaths) {
  TestSupport::TempDir temp_dir("artifact_paths_matrix");
  const auto config_path = writePathMatrixConfig(temp_dir);
  Config config(config_path, false, false);

  using WindowsDiskAnalysis::ConfigUtils::getWithVersionFallback;

  EXPECT_EQ(getWithVersionFallback(config, "Windows7", "PrefetchPath"),
            "WINDOWS\\Prefetch");
  EXPECT_EQ(getWithVersionFallback(config, "Windows8", "PrefetchPath"),
            "Windows\\Prefetch");
  EXPECT_EQ(getWithVersionFallback(config, "Windows10", "PrefetchPath"),
            "Windows\\Prefetch");
  EXPECT_EQ(getWithVersionFallback(config, "Windows11", "PrefetchPath"),
            "Windows\\Prefetch");

  EXPECT_EQ(getWithVersionFallback(config, "Windows7", "AmcachePath"), "");
  EXPECT_EQ(getWithVersionFallback(config, "Windows8", "AmcachePath"),
            "Windows\\appcompat\\Programs\\Amcache.hve");
  EXPECT_EQ(getWithVersionFallback(config, "Windows10", "AmcachePath"),
            "Windows\\appcompat\\Programs\\Amcache.hve");
  EXPECT_EQ(getWithVersionFallback(config, "Windows11", "AmcachePath"),
            "Windows\\appcompat\\Programs\\Amcache.hve");

  EXPECT_EQ(getWithVersionFallback(config, "Windows7", "RecentFileCachePath"),
            "WINDOWS\\AppCompat\\Programs\\RecentFileCache.bcf");
  EXPECT_EQ(getWithVersionFallback(config, "Windows10", "RecentFileCachePath"),
            "");
}

TEST(ArtifactPathsByOsTest, ExecutionHelperNormalizesRegistryHivePathsByVersion) {
  TestSupport::TempDir temp_dir("artifact_paths_execution_helper");
  const auto config_path = writePathMatrixConfig(temp_dir);
  Config config(config_path, false, false);

  using WindowsDiskAnalysis::ExecutionEvidenceDetail::findPathForOsVersion;

  EXPECT_EQ(findPathForOsVersion(config, "OSInfoRegistryPaths", "Windows7"),
            "WINDOWS/system32/config/software");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoRegistryPaths", "Windows8"),
            "Windows/System32/config/SOFTWARE");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoRegistryPaths", "Windows10"),
            "Windows/System32/config/SOFTWARE");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoRegistryPaths", "Windows11"),
            "Windows/System32/config/SOFTWARE");

  EXPECT_EQ(findPathForOsVersion(config, "OSInfoSystemRegistryPaths", "Windows7"),
            "WINDOWS/system32/config/system");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoSystemRegistryPaths", "Windows8"),
            "Windows/System32/config/SYSTEM");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoSystemRegistryPaths", "Windows10"),
            "Windows/System32/config/SYSTEM");
  EXPECT_EQ(findPathForOsVersion(config, "OSInfoSystemRegistryPaths", "Windows11"),
            "Windows/System32/config/SYSTEM");
}
