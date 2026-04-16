/// @file test_pipeline_win7.cpp
/// @brief CLI integration tests — end-to-end pipeline scenarios (Windows 7).

#include <cstdlib>
#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "test_support.hpp"

namespace fs = std::filesystem;

namespace {

std::string runBinary(const std::string& args) {
  const std::string cmd =
      std::string(PROGRAM_TRACES_BINARY_PATH) + " " + args + " 2>&1";
  return TestSupport::runCommand(cmd);
}

int runBinaryExitCode(const std::string& args) {
  const std::string cmd =
      std::string(PROGRAM_TRACES_BINARY_PATH) + " " + args + " 2>&1 ; echo $?";
  const std::string out = TestSupport::runCommand(cmd);
  const auto pos = out.rfind('\n', out.size() > 1 ? out.size() - 2 : 0);
  const std::string last =
      (pos != std::string::npos) ? out.substr(pos + 1) : out;
  try { return std::stoi(last); } catch (...) { return -1; }
}

/// @brief Writes a config that lists only Windows7 as a target version.
std::string writeWin7Config(const TestSupport::TempDir& dir) {
  const std::string ini =
      "[General]\nVersions = Windows7\n"
      "[OSInfoRegistryPaths]\nDefault = WINDOWS/system32/config/SOFTWARE\n"
      "[OSInfoSystemRegistryPaths]\nDefault = WINDOWS/system32/config/SYSTEM\n"
      "[OSInfoHive]\nDefault = Microsoft/Windows NT/CurrentVersion\n"
      "[OSInfoKeys]\nDefault = ProductName,CurrentBuild\n"
      "[Recovery]\nSignatureScanMaxCandidates = 100\n"
      "[VersionDefaults]\nPrefetchPath = WINDOWS/Prefetch\n"
      "AmcachePath =\nAmcacheKeys =\n";
  const auto p = dir.path() / "config_w7.ini";
  TestSupport::writeTextFile(p, ini);
  return p.string();
}

}  // namespace

// ---------------------------------------------------------------------------
// Non-existent Win7 disk root fails cleanly
// ---------------------------------------------------------------------------

TEST(PipelineWin7Test, NonExistentWin7DiskRootFailsCleanly) {
  TestSupport::TempDir dir("pipe_w7_nodisk");
  const auto cfg      = writeWin7Config(dir);
  const auto out_path = (dir.path() / "out_w7.csv").string();
  const int code = runBinaryExitCode(
      "-d /nonexistent_win7_disk -c " + cfg + " -o " + out_path);
  EXPECT_GT(code, 0) << "Non-existent Win7 disk must fail with non-zero exit";
  EXPECT_LE(code, 4) << "Exit code must be within documented range";
}

// ---------------------------------------------------------------------------
// Recovery-only flags work without crashing
// ---------------------------------------------------------------------------

TEST(PipelineWin7Test, RecoveryCsvFlagParsedCorrectly) {
  TestSupport::TempDir dir("pipe_w7_rcov");
  const auto cfg      = writeWin7Config(dir);
  const auto out_path = (dir.path() / "out_w7.csv").string();
  const auto rec_path = (dir.path() / "recovery_w7.csv").string();
  const int code = runBinaryExitCode(
      "-d /nonexistent_w7 -c " + cfg +
      " -o " + out_path +
      " -R " + rec_path);
  // Should fail on OS detection (no real disk), NOT on argument parsing.
  EXPECT_NE(code, 1) << "Argument parsing must not fail for valid -R flag";
  EXPECT_NE(code, -1) << "Binary must not crash";
}

// ---------------------------------------------------------------------------
// Win7 config format: positional arguments still work
// ---------------------------------------------------------------------------

TEST(PipelineWin7Test, PositionalArgumentsAreAccepted) {
  TestSupport::TempDir dir("pipe_w7_pos");
  const auto cfg      = writeWin7Config(dir);
  const auto out_path = (dir.path() / "out_w7.csv").string();
  // Positional form: [disk_root] config.ini output.csv
  const int code = runBinaryExitCode(
      "/nonexistent_w7 " + cfg + " " + out_path);
  // Fails on OS detection — positional parsing must NOT give code 1.
  EXPECT_NE(code, 1)
      << "Positional-argument parsing must succeed for 3-argument form";
  EXPECT_NE(code, -1) << "Binary must not crash";
}

// ---------------------------------------------------------------------------
// Empty args shows help (exit 0)
// ---------------------------------------------------------------------------

TEST(PipelineWin7Test, EmptyArgsShowsHelp) {
  const int code = runBinaryExitCode("");
  EXPECT_EQ(code, 0) << "No-args invocation must show help and exit 0";
}

// ---------------------------------------------------------------------------
// Log file flag is accepted without error
// ---------------------------------------------------------------------------

TEST(PipelineWin7Test, LogFileFlagAcceptedWithoutArgumentError) {
  TestSupport::TempDir dir("pipe_w7_log");
  const auto cfg      = writeWin7Config(dir);
  const auto log_path = (dir.path() / "test.log").string();
  const auto out_path = (dir.path() / "out.csv").string();
  const int code = runBinaryExitCode(
      "-d /nonexistent_w7 -c " + cfg +
      " -o " + out_path +
      " -l " + log_path);
  EXPECT_NE(code, 1) << "-l flag must not cause argument parse error";
  EXPECT_NE(code, -1) << "Binary must not crash";
}
