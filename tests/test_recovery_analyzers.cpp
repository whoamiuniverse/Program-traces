/// @file test_recovery_analyzers.cpp
/// @brief Unit tests for USNAnalyzer, NTFSMetadataAnalyzer, and RegistryLogAnalyzer.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/recovery/fs_metadata/ntfs_metadata_analyzer.hpp"
#include "analysis/artifacts/recovery/registry/registry_log_analyzer.hpp"
#include "analysis/artifacts/recovery/usn/usn_analyzer.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
using namespace WindowsDiskAnalysis;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// @brief Appends ASCII bytes for @p str to @p blob.
void appendAscii(std::vector<uint8_t>& blob, const std::string& str) {
  for (char c : str) {
    blob.push_back(static_cast<uint8_t>(c));
  }
}

/// @brief Appends UTF-16LE bytes for @p str to @p blob.
void appendUtf16Le(std::vector<uint8_t>& blob, const std::string& str) {
  for (char c : str) {
    blob.push_back(static_cast<uint8_t>(c));
    blob.push_back(0x00);
  }
}

/// @brief Creates a config INI file that enables binary-scan fallback.
std::string writeFlatConfig(const TestSupport::TempDir& dir,
                             const std::string& extra = "") {
  const std::string ini =
      "[Recovery]\nEnableUSN=true\nEnableNativeUSNParser=false\n"
      "EnableRegistryLogsRecovery=true\nEnableNTFSMetadata=true\n"
      "EnableNativeFsntfsParser=false\nBinaryScanMaxMB=1\n"
      "MaxCandidatesPerSource=100\n" + extra;
  const auto p = dir.path() / "cfg.ini";
  TestSupport::writeTextFile(p, ini);
  return p.string();
}

/// @brief Checks that at least one evidence entry has @p substr in its path.
bool hasEvidence(const std::vector<RecoveryEvidence>& ev,
                 const std::string& substr) {
  return std::any_of(ev.begin(), ev.end(), [&](const RecoveryEvidence& e) {
    return e.executable_path.find(substr) != std::string::npos ||
           e.details.find(substr) != std::string::npos;
  });
}

}  // namespace

// ===========================================================================
// USNAnalyzer — disabled
// ===========================================================================

TEST(USNAnalyzerTest, DisabledReturnsEmpty) {
  TestSupport::TempDir dir("usn_disabled");
  const std::string ini = "[Recovery]\nEnableUSN=false\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  USNAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

// ===========================================================================
// USNAnalyzer — binary fallback finds ASCII executable paths
// ===========================================================================

TEST(USNAnalyzerTest, BinaryFallbackFindsAsciiExePath) {
  TestSupport::TempDir dir("usn_ascii_exe");
  const auto cfg = writeFlatConfig(dir);

  // Build a blob with a known Windows executable path in ASCII.
  std::vector<uint8_t> blob(512, 0x00);
  const std::string exe_path = "C:\\Windows\\System32\\svchost.exe";
  appendAscii(blob, exe_path);
  // Pad to force the binary scanner to have something surrounding it.
  blob.resize(blob.size() + 256, 0x00);

  // Place blob at the expected USN journal path.
  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty())
      << "Binary fallback should find the ASCII .exe path";
  EXPECT_TRUE(hasEvidence(results, "svchost"))
      << "Found evidence must reference svchost";
}

TEST(USNAnalyzerTest, BinaryFallbackFindsUtf16LeExePath) {
  TestSupport::TempDir dir("usn_utf16_exe");
  const auto cfg = writeFlatConfig(dir);

  std::vector<uint8_t> blob(512, 0x00);
  const std::string exe_path = "C:\\Windows\\explorer.exe";
  appendUtf16Le(blob, exe_path);
  blob.resize(blob.size() + 256, 0x00);

  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty())
      << "Binary fallback should find the UTF-16LE .exe path";
  EXPECT_TRUE(hasEvidence(results, "explorer"))
      << "Found evidence must reference explorer";
}

TEST(USNAnalyzerTest, NonExecutableStringsAreIgnored) {
  TestSupport::TempDir dir("usn_no_exec");
  const auto cfg = writeFlatConfig(dir);

  // Embed only a non-executable file reference.
  std::vector<uint8_t> blob(512, 0x00);
  appendAscii(blob, "C:\\Users\\test\\document.docx");
  blob.resize(blob.size() + 256, 0x00);

  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_TRUE(results.empty())
      << "Non-executable paths (.docx) must be ignored by the binary scanner";
}

TEST(USNAnalyzerTest, EmptyJournalProducesNoResults) {
  TestSupport::TempDir dir("usn_empty");
  const auto cfg = writeFlatConfig(dir);

  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", {});

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(USNAnalyzerTest, MissingJournalProducesNoResults) {
  TestSupport::TempDir dir("usn_missing");
  const auto cfg = writeFlatConfig(dir);
  // No $UsnJrnl file created.
  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

// ===========================================================================
// RegistryLogAnalyzer — binary scan on .LOG1/.LOG2 files
// ===========================================================================

TEST(RegistryLogAnalyzerTest, DisabledReturnsEmpty) {
  TestSupport::TempDir dir("reglog_disabled");
  const std::string ini = "[Recovery]\nEnableRegistryLogsRecovery=false\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  RegistryLogAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(RegistryLogAnalyzerTest, FindsExePathInLog1File) {
  TestSupport::TempDir dir("reglog_log1");
  const auto cfg = writeFlatConfig(dir);

  // Create config directory with a .LOG1 file containing an executable path.
  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> blob(256, 0x00);
  appendAscii(blob, "C:\\Windows\\System32\\notepad.exe");
  blob.resize(blob.size() + 256, 0x00);
  TestSupport::writeBinaryFile(cfg_dir / "SOFTWARE.LOG1", blob);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty())
      << "Should find .exe path inside .LOG1 file";
  EXPECT_TRUE(hasEvidence(results, "notepad"))
      << "Evidence should reference notepad.exe";
}

TEST(RegistryLogAnalyzerTest, FindsExePathInLog2File) {
  TestSupport::TempDir dir("reglog_log2");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> blob(256, 0x00);
  appendAscii(blob, "C:\\Program Files\\App\\malware.exe");
  blob.resize(blob.size() + 256, 0x00);
  TestSupport::writeBinaryFile(cfg_dir / "SYSTEM.LOG2", blob);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty()) << "Should find .exe in .LOG2 file";
  EXPECT_TRUE(hasEvidence(results, "malware")) << "Should reference malware.exe";
}

TEST(RegistryLogAnalyzerTest, NonLogFilesAreIgnored) {
  TestSupport::TempDir dir("reglog_ignore");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  // Embed executable in a plain file (not .LOG1/.LOG2/.blf/.regtrans-ms).
  std::vector<uint8_t> blob(256, 0x00);
  appendAscii(blob, "C:\\Windows\\System32\\calc.exe");
  blob.resize(blob.size() + 256, 0x00);
  TestSupport::writeBinaryFile(cfg_dir / "SOFTWARE.dat", blob);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_TRUE(results.empty())
      << "Non-transaction-log files must be ignored";
}

TEST(RegistryLogAnalyzerTest, EvidenceHasTamperFlag) {
  TestSupport::TempDir dir("reglog_flag");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> blob(256, 0x00);
  appendAscii(blob, "C:\\Windows\\regedit.exe");
  blob.resize(blob.size() + 256, 0x00);
  TestSupport::writeBinaryFile(cfg_dir / "NTUSER.LOG1", blob);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  ASSERT_FALSE(results.empty());
  EXPECT_EQ(results.front().tamper_flag, "registry_transaction_log_evidence")
      << "RegistryLog evidence must carry the tamper flag";
}

// ===========================================================================
// NTFSMetadataAnalyzer — binary scan on synthetic $MFT
// ===========================================================================

TEST(NTFSMetadataAnalyzerTest, DisabledReturnsEmpty) {
  TestSupport::TempDir dir("ntfs_disabled");
  const std::string ini = "[Recovery]\nEnableNTFSMetadata=false\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  NTFSMetadataAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(NTFSMetadataAnalyzerTest, BinaryFallbackFindsMftRecordWithExe) {
  TestSupport::TempDir dir("ntfs_mft_exe");
  // Use BinaryScanMaxMB=1, disable native parser.
  const auto cfg = writeFlatConfig(dir,
      "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  // Build a minimal 1024-byte MFT record: starts with FILE signature,
  // followed by padding + ASCII executable path.
  std::vector<uint8_t> record(1024, 0x00);
  // FILE signature at offset 0
  record[0] = 'F'; record[1] = 'I'; record[2] = 'L'; record[3] = 'E';
  // flags at 0x16: 0x01 = in_use
  record[0x16] = 0x01;
  // attribute offset at 0x14 - point past record header (0x38)
  record[0x14] = 0x38;
  // attribute type list terminator 0xFFFFFFFF at offset 0x38
  record[0x38] = 0xFF; record[0x39] = 0xFF;
  record[0x3A] = 0xFF; record[0x3B] = 0xFF;
  // Embed executable path in the tail of the record.
  const std::string exe = "C:\\Windows\\System32\\lsass.exe";
  for (std::size_t i = 0; i < exe.size() && (512 + i) < record.size(); ++i) {
    record[512 + i] = static_cast<uint8_t>(exe[i]);
  }

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty())
      << "Binary fallback should find .exe path inside FILE record";
  EXPECT_TRUE(hasEvidence(results, "lsass"))
      << "Evidence should reference lsass.exe";
}

TEST(NTFSMetadataAnalyzerTest, RecordWithoutFileSignatureIsSkipped) {
  TestSupport::TempDir dir("ntfs_no_sig");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  // Record without FILE signature.
  std::vector<uint8_t> record(1024, 0x00);
  const std::string exe = "C:\\Windows\\winlogon.exe";
  for (std::size_t i = 0; i < exe.size(); ++i) {
    record[512 + i] = static_cast<uint8_t>(exe[i]);
  }
  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_TRUE(results.empty())
      << "Records without FILE signature must be skipped";
}

TEST(NTFSMetadataAnalyzerTest, SiFnDivergenceFlagSetWhenTimestampsDeviate) {
  TestSupport::TempDir dir("ntfs_si_fn");
  // Lower threshold to 1 second to ensure divergence is triggered.
  const auto cfg = writeFlatConfig(dir,
      "MFTRecordSize=1024\nMFTMaxRecords=10\n"
      "[TamperRules]\nEnableSIFNDivergenceCheck=true\n"
      "TimestampDivergenceThresholdSec=1\n");

  // Build a FILE record with $SI (0x10) and $FN (0x30) attributes that have
  // significantly different creation timestamps.
  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F'; record[1] = 'I'; record[2] = 'L'; record[3] = 'E';
  record[0x16] = 0x01;  // in_use

  // Attribute list starts at 0x38.
  record[0x14] = 0x38;
  std::size_t attr_off = 0x38;

  // Helper to write a LE uint32 at position p.
  auto writeU32 = [&](std::size_t p, uint32_t v) {
    record[p]   = static_cast<uint8_t>(v & 0xFF);
    record[p+1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    record[p+2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    record[p+3] = static_cast<uint8_t>((v >> 24) & 0xFF);
  };
  auto writeU64 = [&](std::size_t p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
      record[p + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
  };
  auto writeU16 = [&](std::size_t p, uint16_t v) {
    record[p]   = static_cast<uint8_t>(v & 0xFF);
    record[p+1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  };

  // $STANDARD_INFORMATION (0x10): 72-byte resident attribute.
  // creation time at content_start = attr_off + content_offset (0x18 → 24)
  const uint64_t si_creation = 132000000000000000ULL;  // ~2019-01-01
  writeU32(attr_off, 0x10);          // type
  writeU32(attr_off + 4, 72);        // attribute size
  record[attr_off + 8] = 0;          // resident
  writeU32(attr_off + 16, 48);       // content size
  writeU16(attr_off + 20, 24);       // content offset
  writeU64(attr_off + 24, si_creation);

  // $FILE_NAME (0x30): 72-byte resident attribute immediately after.
  attr_off += 72;
  const uint64_t fn_creation = 132500000000000000ULL;  // ~2021-01-01 (2yr later)
  writeU32(attr_off, 0x30);          // type
  writeU32(attr_off + 4, 72);        // attribute size
  record[attr_off + 8] = 0;          // resident
  writeU32(attr_off + 16, 48);       // content size
  writeU16(attr_off + 20, 24);       // content offset
  // $FILE_NAME content: parent ref (8 bytes), creation at offset+8
  writeU64(attr_off + 24 + 8, fn_creation);

  // Terminator.
  attr_off += 72;
  writeU32(attr_off, 0xFFFFFFFFU);

  // Embed executable path in the tail.
  const std::string exe = "C:\\Windows\\System32\\services.exe";
  for (std::size_t i = 0; i < exe.size() && (600 + i) < record.size(); ++i) {
    record[600 + i] = static_cast<uint8_t>(exe[i]);
  }

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  ASSERT_FALSE(results.empty());
  const bool has_divergence = std::any_of(
      results.begin(), results.end(), [](const RecoveryEvidence& ev) {
        return ev.tamper_flag == "mft_si_fn_divergence";
      });
  EXPECT_TRUE(has_divergence)
      << "Large SI/FN timestamp gap must set mft_si_fn_divergence flag";
}
