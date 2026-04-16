/// @file test_pipeline_win10.cpp
/// @brief CLI integration tests — end-to-end pipeline scenarios (Windows 10).

#include <cstdlib>
#include <filesystem>
#include <fstream>
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
  // Last line is the exit code.
  const auto pos = out.rfind('\n', out.size() > 1 ? out.size() - 2 : 0);
  const std::string last =
      (pos != std::string::npos) ? out.substr(pos + 1) : out;
  try { return std::stoi(last); } catch (...) { return -1; }
}

/// @brief Creates a minimal config INI for testing.
std::string writeFakeConfig(const TestSupport::TempDir& dir) {
  // Point hive paths somewhere that doesn't exist so the analyzer hits the
  // auto-select path and fails cleanly rather than crashing.
  const std::string ini =
      "[General]\nVersions = Windows10\n"
      "[OSInfoRegistryPaths]\nDefault = Windows/System32/config/SOFTWARE\n"
      "[OSInfoSystemRegistryPaths]\nDefault = Windows/System32/config/SYSTEM\n"
      "[OSInfoHive]\nDefault = Microsoft/Windows NT/CurrentVersion\n"
      "[OSInfoKeys]\nDefault = ProductName\n"
      "[Recovery]\nSignatureScanMaxCandidates = 100\n";
  const auto p = dir.path() / "config.ini";
  TestSupport::writeTextFile(p, ini);
  return p.string();
}

}  // namespace

// ---------------------------------------------------------------------------
// Help output includes --image flag
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, HelpOutputIncludesImageFlag) {
  const std::string out = runBinary("--help");
  EXPECT_NE(out.find("-i, --image"), std::string::npos)
      << "Help must document --image / -i flag";
}

// ---------------------------------------------------------------------------
// Missing required arguments → exit code 1 (kExitInvalidArguments)
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, MissingConfigAndOutputExitsWithError) {
  const int code = runBinaryExitCode("--disk-root /nonexistent");
  EXPECT_EQ(code, 1) << "Missing -c/-o must exit with code 1";
}

TEST(PipelineWin10Test, MissingImageValueExitsWithError) {
  TestSupport::TempDir dir("pipe_w10_missing_img");
  const auto cfg = writeFakeConfig(dir);
  const int code =
      runBinaryExitCode("-c " + cfg + " -o out.csv --image");
  EXPECT_EQ(code, 1) << "--image with no value must exit with code 1";
}

// ---------------------------------------------------------------------------
// Non-existent disk root → exit with analysis error (code 2 or 3), no crash
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, NonExistentDiskRootFailsCleanly) {
  TestSupport::TempDir dir("pipe_w10_nodisk");
  const auto cfg  = writeFakeConfig(dir);
  const auto out_path = (dir.path() / "out.csv").string();
  const int code = runBinaryExitCode(
      "-d /nonexistent_disk_w10 -c " + cfg + " -o " + out_path);
  // Must not be 0 (success) and must not be negative (crash/signal).
  EXPECT_GT(code, 0) << "Non-existent disk root must exit with error";
  EXPECT_LE(code, 4) << "Exit code must be within documented range";
}

// ---------------------------------------------------------------------------
// Recovery CSV path identical to main output → exit code 1
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, DuplicateRecoveryOutputPathExitsWithError) {
  TestSupport::TempDir dir("pipe_w10_dup_csv");
  const auto cfg = writeFakeConfig(dir);
  const int code = runBinaryExitCode(
      "-c " + cfg + " -o same.csv -R same.csv");
  EXPECT_EQ(code, 1)
      << "Recovery CSV path == output path must exit with code 1";
}

// ---------------------------------------------------------------------------
// Signature scan with valid --image on a real file — must not crash
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, ImageFlagWithExistingFileDoesNotCrash) {
  TestSupport::TempDir dir("pipe_w10_img_flag");
  const auto cfg = writeFakeConfig(dir);
  // Write a small synthetic image (just random bytes — no signatures).
  const std::vector<uint8_t> dummy(1024, 0xAB);
  TestSupport::writeBinaryFile(dir.path() / "disk.img", dummy);
  const auto out_path = (dir.path() / "out.csv").string();
  const int code = runBinaryExitCode(
      "-d /nonexistent_w10_img -c " + cfg +
      " -o " + out_path +
      " --image " + (dir.path() / "disk.img").string());
  // Fails on OS detection (no real disk), but must not crash (code != -1).
  EXPECT_NE(code, -1) << "Binary must not crash when --image is supplied";
  EXPECT_LE(code, 4)  << "Exit code must be within documented range";
}

// ---------------------------------------------------------------------------
// Version output is stable
// ---------------------------------------------------------------------------

TEST(PipelineWin10Test, VersionOutputContainsProgramName) {
  const std::string out = runBinary("-v");
  EXPECT_NE(out.find("Program traces"), std::string::npos);
}
