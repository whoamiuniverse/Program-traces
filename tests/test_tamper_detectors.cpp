/// @file test_tamper_detectors.cpp
/// @brief Unit tests for tamper signal detectors.

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/execution/execution_evidence_config.hpp"
#include "analysis/artifacts/execution/execution_evidence_context.hpp"
#include "analysis/artifacts/execution/tamper/artifact_presence_tamper_detector.hpp"
#include "analysis/artifacts/execution/tamper/system_log_tamper_detector.hpp"
#include "analysis/artifacts/execution/tamper/registry_state_tamper_detector.hpp"
#include "infra/cli/cli_options.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

bool hasFlag(const std::vector<std::string>& flags, const std::string& flag) {
  return std::find(flags.begin(), flags.end(), flag) != flags.end();
}

/// @brief Builds a minimal ExecutionEvidenceContext for testing.
ExecutionEvidenceContext makeCtx(const std::string& disk_root,
                                  const ExecutionEvidenceConfig& cfg,
                                  const std::string& system_hive = "",
                                  const std::string& software_hive = "") {
  return ExecutionEvidenceContext{
      .disk_root          = disk_root,
      .software_hive_path = software_hive,
      .system_hive_path   = system_hive,
      .config             = cfg,
  };
}

}  // namespace

// ===========================================================================
// ArtifactPresenceTamperDetector
// ===========================================================================

TEST(ArtifactPresenceTamperDetectorTest, SkippedWhenDisabled) {
  TestSupport::TempDir dir("tamper_pres_disabled");
  ExecutionEvidenceConfig cfg;
  cfg.enable_artifact_presence_tamper_check = false;

  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(flags.empty());
}

TEST(ArtifactPresenceTamperDetectorTest, FlagsAmcacheMissingWhenAbsent) {
  TestSupport::TempDir dir("tamper_amcache_missing");
  // No Amcache.hve created
  ExecutionEvidenceConfig cfg;
  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(hasFlag(flags, "amcache_missing"))
      << "Should flag amcache_missing when Amcache.hve is absent";
}

TEST(ArtifactPresenceTamperDetectorTest, NoAmcacheFlagWhenPresent) {
  TestSupport::TempDir dir("tamper_amcache_present");
  // Create Amcache.hve at expected location
  const auto amcache_path = dir.path() / "Windows/AppCompat/Programs/Amcache.hve";
  TestSupport::writeTextFile(amcache_path, "dummy");

  ExecutionEvidenceConfig cfg;
  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_FALSE(hasFlag(flags, "amcache_missing"))
      << "Should not flag amcache_missing when Amcache.hve exists";
}

TEST(ArtifactPresenceTamperDetectorTest, FlagsUsnJournalDisabledWhenAbsent) {
  TestSupport::TempDir dir("tamper_usn_missing");
  // Provide Amcache to avoid that flag
  TestSupport::writeTextFile(
      dir.path() / "Windows/AppCompat/Programs/Amcache.hve", "dummy");

  ExecutionEvidenceConfig cfg;
  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(hasFlag(flags, "usn_journal_disabled"))
      << "Should flag usn_journal_disabled when $UsnJrnl is absent";
}

TEST(ArtifactPresenceTamperDetectorTest, NoDuplicateFlagsOnMultipleCalls) {
  TestSupport::TempDir dir("tamper_no_dup");
  ExecutionEvidenceConfig cfg;
  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);
  detector.detect(ctx, flags);

  const auto amcache_count = std::count(flags.begin(), flags.end(), "amcache_missing");
  EXPECT_LE(amcache_count, 1) << "Flag must not be duplicated";
}

TEST(ArtifactPresenceTamperDetectorTest, FlagsVssCopiesDeletedWhenSviEmptyOrMissing) {
  TestSupport::TempDir dir("tamper_vss_empty");
  // Provide Amcache + USN placeholder to focus on VSS
  TestSupport::writeTextFile(
      dir.path() / "Windows/AppCompat/Programs/Amcache.hve", "dummy");
  // Create SVI directory but leave it empty
  fs::create_directories(dir.path() / "System Volume Information");

  ExecutionEvidenceConfig cfg;
  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  ArtifactPresenceTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(hasFlag(flags, "volume_shadow_copies_deleted"))
      << "Should flag volume_shadow_copies_deleted when SVI exists but has no snapshots";
}

// ===========================================================================
// SystemLogTamperDetector
// ===========================================================================

TEST(SystemLogTamperDetectorTest, SkippedWhenDisabled) {
  TestSupport::TempDir dir("tamper_syslog_disabled");
  ExecutionEvidenceConfig cfg;
  cfg.enable_system_log_tamper_check = false;

  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  SystemLogTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(flags.empty());
}

TEST(SystemLogTamperDetectorTest, NoFlagWhenSystemLogAbsent) {
  // When the log file doesn't exist, detector must not crash and must not flag.
  TestSupport::TempDir dir("tamper_syslog_absent");
  ExecutionEvidenceConfig cfg;
  cfg.system_log_path = "Windows/System32/winevt/Logs/System.evtx";

  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  SystemLogTamperDetector detector;
  EXPECT_NO_THROW(detector.detect(ctx, flags));
  // No file → no evidence of clearing → no flag expected
  EXPECT_FALSE(hasFlag(flags, "system_log_cleared"));
}

// ===========================================================================
// RegistryStateTamperDetector
// ===========================================================================

TEST(RegistryStateTamperDetectorTest, SkippedWhenDisabled) {
  TestSupport::TempDir dir("tamper_reg_disabled");
  ExecutionEvidenceConfig cfg;
  cfg.enable_registry_state_tamper_check = false;

  const auto ctx = makeCtx(dir.path().string(), cfg);
  std::vector<std::string> flags;
  RegistryStateTamperDetector detector;
  detector.detect(ctx, flags);

  EXPECT_TRUE(flags.empty());
}

TEST(RegistryStateTamperDetectorTest, NoFlagWhenSystemHiveAbsent) {
  // Missing hive → detector must not crash, no flags raised.
  TestSupport::TempDir dir("tamper_reg_absent");
  ExecutionEvidenceConfig cfg;

  const auto ctx = makeCtx(dir.path().string(), cfg,
                            /*system_hive=*/(dir.path() / "nonexistent_SYSTEM").string());
  std::vector<std::string> flags;
  RegistryStateTamperDetector detector;
  EXPECT_NO_THROW(detector.detect(ctx, flags));
  EXPECT_FALSE(hasFlag(flags, "prefetch_disabled"));
  EXPECT_FALSE(hasFlag(flags, "event_log_service_disabled"));
}

// ===========================================================================
// --image CLI flag integration
// ===========================================================================

TEST(CliImageFlagTest, ParsesShortImageFlag) {
  using ProgramTraces::Cli::parseArguments;

  std::vector<std::string> args = {
      "program_traces", "-c", "config.ini", "-o", "out.csv",
      "-i", "/path/to/disk.img"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& a : args) argv.push_back(a.data());

  std::string err;
  auto opts = parseArguments(static_cast<int>(argv.size()), argv.data(), err);
  ASSERT_TRUE(opts.has_value()) << err;
  EXPECT_EQ(opts->image_path, "/path/to/disk.img");
}

TEST(CliImageFlagTest, ParsesLongImageFlag) {
  using ProgramTraces::Cli::parseArguments;

  std::vector<std::string> args = {
      "program_traces", "-c", "config.ini", "-o", "out.csv",
      "--image", "/mnt/evidence/disk.raw"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& a : args) argv.push_back(a.data());

  std::string err;
  auto opts = parseArguments(static_cast<int>(argv.size()), argv.data(), err);
  ASSERT_TRUE(opts.has_value()) << err;
  EXPECT_EQ(opts->image_path, "/mnt/evidence/disk.raw");
}

TEST(CliImageFlagTest, ImagePathEmptyWhenNotSpecified) {
  using ProgramTraces::Cli::parseArguments;

  std::vector<std::string> args = {
      "program_traces", "-c", "config.ini", "-o", "out.csv"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& a : args) argv.push_back(a.data());

  std::string err;
  auto opts = parseArguments(static_cast<int>(argv.size()), argv.data(), err);
  ASSERT_TRUE(opts.has_value()) << err;
  EXPECT_TRUE(opts->image_path.empty());
}

TEST(CliImageFlagTest, FailsWhenImageFlagHasNoValue) {
  using ProgramTraces::Cli::parseArguments;

  std::vector<std::string> args = {
      "program_traces", "-c", "config.ini", "-o", "out.csv", "-i"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& a : args) argv.push_back(a.data());

  std::string err;
  auto opts = parseArguments(static_cast<int>(argv.size()), argv.data(), err);
  EXPECT_FALSE(opts.has_value());
  EXPECT_FALSE(err.empty());
}
