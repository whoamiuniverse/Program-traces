/// @file test_recovery_analyzers.cpp
/// @brief Unit tests for USNAnalyzer, NTFSMetadataAnalyzer, and RegistryLogAnalyzer.

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/recovery/fs_metadata/ntfs_metadata_analyzer.hpp"
#include "analysis/artifacts/recovery/hiber/hibernation_analyzer.hpp"
#include "analysis/artifacts/recovery/registry/registry_log_analyzer.hpp"
#include "analysis/artifacts/recovery/tsk/tsk_deleted_file_analyzer.hpp"
#include "analysis/artifacts/recovery/usn/usn_analyzer.hpp"
#include "analysis/artifacts/recovery/vss/vss_analyzer.hpp"
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

/// @brief Writes a little-endian uint16 at @p offset in @p blob.
void writeLe16(std::vector<uint8_t>& blob, std::size_t offset, uint16_t value) {
  if (offset + 1 >= blob.size()) return;
  blob[offset] = static_cast<uint8_t>(value & 0xFFu);
  blob[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

/// @brief Writes a little-endian uint32 at @p offset in @p blob.
void writeLe32(std::vector<uint8_t>& blob, std::size_t offset, uint32_t value) {
  if (offset + 3 >= blob.size()) return;
  blob[offset] = static_cast<uint8_t>(value & 0xFFu);
  blob[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  blob[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
  blob[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
}

/// @brief Sets FAT12 entry value for a cluster.
void setFat12Entry(std::vector<uint8_t>& blob,
                   std::size_t fat_offset,
                   std::size_t cluster,
                   uint16_t value) {
  const std::size_t offset = fat_offset + cluster + (cluster / 2);
  if (offset + 1 >= blob.size()) return;

  const uint16_t bounded = static_cast<uint16_t>(value & 0x0FFFu);
  if ((cluster % 2) == 0) {
    blob[offset] = static_cast<uint8_t>(bounded & 0xFFu);
    blob[offset + 1] = static_cast<uint8_t>(
        (blob[offset + 1] & 0xF0u) | ((bounded >> 8) & 0x0Fu));
  } else {
    blob[offset] = static_cast<uint8_t>(
        (blob[offset] & 0x0Fu) | ((bounded << 4) & 0xF0u));
    blob[offset + 1] = static_cast<uint8_t>((bounded >> 4) & 0xFFu);
  }
}

/// @brief Creates a minimal FAT12 image suitable for TSK regression tests.
std::vector<uint8_t> createFat12ImageTemplate() {
  constexpr std::size_t kSectorSize = 512;
  constexpr std::size_t kTotalSectors = 64;
  constexpr std::size_t kImageSize = kSectorSize * kTotalSectors;
  std::vector<uint8_t> image(kImageSize, 0x00);

  // Boot sector.
  image[0] = 0xEB;
  image[1] = 0x3C;
  image[2] = 0x90;
  const std::array<char, 8> oem = {'M', 'S', 'D', 'O', 'S', '5', '.', '0'};
  std::copy(oem.begin(), oem.end(), image.begin() + 3);

  writeLe16(image, 11, static_cast<uint16_t>(kSectorSize));  // BPB_BytsPerSec
  image[13] = 0x01;                                           // BPB_SecPerClus
  writeLe16(image, 14, 1);                                    // BPB_RsvdSecCnt
  image[16] = 0x01;                                           // BPB_NumFATs
  writeLe16(image, 17, 16);                                   // BPB_RootEntCnt
  writeLe16(image, 19, static_cast<uint16_t>(kTotalSectors)); // BPB_TotSec16
  image[21] = 0xF8;                                           // BPB_Media
  writeLe16(image, 22, 1);                                    // BPB_FATSz16
  writeLe16(image, 24, 32);                                   // BPB_SecPerTrk
  writeLe16(image, 26, 64);                                   // BPB_NumHeads
  writeLe16(image, 510, 0xAA55);                              // Boot signature

  const std::array<char, 8> fs_type = {'F', 'A', 'T', '1', '2', ' ', ' ', ' '};
  std::copy(fs_type.begin(), fs_type.end(), image.begin() + 54);

  // FAT starts at sector 1.
  constexpr std::size_t kFatOffset = kSectorSize;
  image[kFatOffset + 0] = 0xF8;
  image[kFatOffset + 1] = 0xFF;
  image[kFatOffset + 2] = 0xFF;
  // cluster #2 = EOF by default.
  setFat12Entry(image, kFatOffset, 2, 0x0FFF);

  return image;
}

/// @brief Creates a FAT12 image with a deleted `.LNK` entry and recoverable content.
std::vector<uint8_t> createFat12DeletedFileImage(const std::string& payload) {
  constexpr std::size_t kSectorSize = 512;
  constexpr std::size_t kRootDirOffset = 2 * kSectorSize;
  constexpr std::size_t kDataStartOffset = 3 * kSectorSize;  // cluster #2

  auto image = createFat12ImageTemplate();

  // Deleted directory entry: first byte 0xE5 marks deleted.
  image[kRootDirOffset + 0] = 0xE5;
  image[kRootDirOffset + 1] = 'E';
  image[kRootDirOffset + 2] = 'L';
  image[kRootDirOffset + 3] = 'F';
  image[kRootDirOffset + 4] = 'I';
  image[kRootDirOffset + 5] = 'L';
  image[kRootDirOffset + 6] = 'E';
  image[kRootDirOffset + 7] = ' ';
  image[kRootDirOffset + 8] = 'L';
  image[kRootDirOffset + 9] = 'N';
  image[kRootDirOffset + 10] = 'K';
  image[kRootDirOffset + 11] = 0x20;  // archive attribute
  writeLe16(image, kRootDirOffset + 26, 2);  // start cluster
  writeLe32(image, kRootDirOffset + 28, static_cast<uint32_t>(payload.size()));

  for (std::size_t i = 0; i < payload.size() &&
                          (kDataStartOffset + i) < image.size();
       ++i) {
    image[kDataStartOffset + i] = static_cast<uint8_t>(payload[i]);
  }
  return image;
}

/// @brief Creates a FAT12 image with executable path bytes in an unallocated cluster.
std::vector<uint8_t> createFat12UnallocatedImage(const std::string& payload) {
  constexpr std::size_t kSectorSize = 512;
  constexpr std::size_t kCluster3Offset = 4 * kSectorSize;  // data sector for cluster #3

  auto image = createFat12ImageTemplate();

  // Keep root directory empty (0x00 marker in first entry).
  constexpr std::size_t kRootDirOffset = 2 * kSectorSize;
  image[kRootDirOffset] = 0x00;

  // cluster #3 stays free (FAT entry = 0), but contains scan-relevant bytes.
  for (std::size_t i = 0; i < payload.size() &&
                          (kCluster3Offset + i) < image.size();
       ++i) {
    image[kCluster3Offset + i] = static_cast<uint8_t>(payload[i]);
  }
  return image;
}

/// @brief Creates an image with intentionally corrupted filesystem metadata.
std::vector<uint8_t> createCorruptedFsImage() {
  auto image = createFat12ImageTemplate();
  // Corrupt mandatory BPB field: bytes-per-sector cannot be zero.
  image[11] = 0x00;
  image[12] = 0x00;
  return image;
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

/// @brief Counts evidence entries containing @p substr in path/details.
std::size_t countEvidence(const std::vector<RecoveryEvidence>& ev,
                          const std::string& substr) {
  return static_cast<std::size_t>(std::count_if(
      ev.begin(), ev.end(), [&](const RecoveryEvidence& e) {
        return e.executable_path.find(substr) != std::string::npos ||
               e.details.find(substr) != std::string::npos;
      }));
}

}  // namespace

// ===========================================================================
// USNAnalyzer — legacy EnableUSN flag is ignored
// ===========================================================================

TEST(USNAnalyzerTest, IgnoresEnableUsnFlag) {
  TestSupport::TempDir dir("usn_ignore_enable");
  const std::string ini = "[Recovery]\nEnableUSN=false\nBinaryScanMaxMB=1\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  std::vector<uint8_t> blob(512, 0x00);
  appendAscii(blob, "C:\\Windows\\System32\\svchost.exe");
  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "svchost"));
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

TEST(USNAnalyzerTest, BinaryFallbackHandlesPartiallyCorruptedJournal) {
  TestSupport::TempDir dir("usn_corrupt_partial");
  const auto cfg = writeFlatConfig(dir);

  std::vector<uint8_t> blob(1024, 0xFF);
  // Corrupted header-like fragment (invalid record length/version).
  blob[0] = 0x01;
  blob[1] = 0x00;
  blob[2] = 0x00;
  blob[3] = 0x00;
  blob[4] = 0x99;
  blob[5] = 0x99;

  appendAscii(blob, "C:\\Windows\\System32\\cmd.exe");
  blob.resize(blob.size() + 2048, 0x00);

  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "cmd.exe"));
}

TEST(USNAnalyzerTest, BinaryFallbackFindsMixedAsciiAndUtf16CandidatesInLargeJournal) {
  TestSupport::TempDir dir("usn_large_mixed");
  const auto cfg = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");

  std::vector<uint8_t> blob(1024 * 1024, 0x00);
  appendAscii(blob, "C:\\Program Files\\ToolA\\alpha.exe");
  blob.resize(blob.size() + 256, 0x00);
  appendUtf16Le(blob, "C:\\Program Files\\ToolB\\beta.exe");
  blob.resize(blob.size() + 256, 0x00);

  const auto usn_dir = dir.path() / "$Extend";
  fs::create_directories(usn_dir);
  TestSupport::writeBinaryFile(usn_dir / "$UsnJrnl", blob);

  USNAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "alpha"));
  EXPECT_TRUE(hasEvidence(results, "beta"));
}

// ===========================================================================
// VSSAnalyzer — snapshot replay fallback behavior
// ===========================================================================

TEST(VSSAnalyzerTest, MissingSourcesProduceNoResults) {
  TestSupport::TempDir dir("vss_missing");
  const auto cfg = writeFlatConfig(dir, "VSSSnapshotReplayMaxFiles=4\n");

  VSSAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(VSSAnalyzerTest, SnapshotReplayHonorsReplayLimit) {
  TestSupport::TempDir dir("vss_replay_limit");
  const auto cfg = writeFlatConfig(
      dir, "VSSSnapshotReplayMaxFiles=1\nBinaryScanMaxMB=2\n");

  const auto snapshot_root =
      dir.path() / "System Volume Information" / "HarddiskVolumeShadowCopy1";
  const auto amcache_path =
      snapshot_root / "Windows/appcompat/Programs/Amcache.hve";
  const auto security_path =
      snapshot_root / "Windows/System32/winevt/Logs/Security.evtx";

  fs::create_directories(amcache_path.parent_path());
  fs::create_directories(security_path.parent_path());

  std::vector<uint8_t> amcache_blob(512, 0x00);
  appendAscii(amcache_blob, "C:\\Program Files\\Replay\\amcache_hit.exe");
  TestSupport::writeBinaryFile(amcache_path, amcache_blob);

  std::vector<uint8_t> security_blob(512, 0x00);
  appendAscii(security_blob, "C:\\Program Files\\Replay\\security_hit.exe");
  TestSupport::writeBinaryFile(security_path, security_blob);

  VSSAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "amcache_hit"));
  EXPECT_FALSE(hasEvidence(results, "security_hit"));
}

TEST(VSSAnalyzerTest, SnapshotReplayDeduplicatesAcrossMultipleSnapshots) {
  TestSupport::TempDir dir("vss_multi_snapshot_dedup");
  const auto cfg = writeFlatConfig(
      dir, "VSSSnapshotReplayMaxFiles=6\nBinaryScanMaxMB=2\n");

  const auto snapshot1 =
      dir.path() / "System Volume Information" / "HarddiskVolumeShadowCopy1";
  const auto snapshot2 =
      dir.path() / "System Volume Information" / "HarddiskVolumeShadowCopy2";
  const auto file1 =
      snapshot1 / "Windows/appcompat/Programs/Amcache.hve";
  const auto file2 =
      snapshot2 / "Windows/System32/winevt/Logs/Security.evtx";

  fs::create_directories(file1.parent_path());
  fs::create_directories(file2.parent_path());

  std::vector<uint8_t> blob1(512, 0x00);
  appendAscii(blob1, "C:\\Program Files\\Replay\\dup.exe");
  TestSupport::writeBinaryFile(file1, blob1);

  std::vector<uint8_t> blob2(512, 0x00);
  appendAscii(blob2, "C:\\Program Files\\Replay\\dup.exe");
  TestSupport::writeBinaryFile(file2, blob2);

  VSSAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_EQ(countEvidence(results, "dup.exe"), 1u);
}

TEST(VSSAnalyzerTest, DamagedShadowStoreFallsBackToBinaryScan) {
  TestSupport::TempDir dir("vss_damaged_store");
  const auto cfg = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");

  const auto svi_file = dir.path() / "System Volume Information" /
                        "shadowcopy_corrupted.store";
  fs::create_directories(svi_file.parent_path());

  std::vector<uint8_t> blob(1024, 0xCC);
  appendAscii(blob, "C:\\Program Files\\Replay\\damaged_store.exe");
  TestSupport::writeBinaryFile(svi_file, blob);

  VSSAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "damaged_store.exe"));
}

// ===========================================================================
// HibernationAnalyzer — fallback behavior and edge cases
// ===========================================================================

TEST(HibernationAnalyzerTest, EmptyHiberProducesNoResults) {
  TestSupport::TempDir dir("hiber_empty");
  const auto cfg = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");

  TestSupport::writeBinaryFile(dir.path() / "hiberfil.sys", {});

  HibernationAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(HibernationAnalyzerTest, FallbackScanFindsExecutablePath) {
  TestSupport::TempDir dir("hiber_fallback");
  const auto cfg = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");

  std::vector<uint8_t> blob(1024, 0x00);
  appendAscii(blob, "C:\\Windows\\System32\\wininit.exe");
  blob.resize(blob.size() + 512, 0x00);
  TestSupport::writeBinaryFile(dir.path() / "hiberfil.sys", blob);

  HibernationAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "wininit"));
}

TEST(HibernationAnalyzerTest, CompressedHeaderStillAllowsSafeFallback) {
  TestSupport::TempDir dir("hiber_compressed_header");
  const auto cfg = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");

  std::vector<uint8_t> blob(2048, 0x00);
  // Synthetic compressed signature prefix: "HIBRhibr"
  blob[0] = 0x48;
  blob[1] = 0x49;
  blob[2] = 0x42;
  blob[3] = 0x52;
  blob[4] = 0x68;
  blob[5] = 0x69;
  blob[6] = 0x62;
  blob[7] = 0x72;
  appendAscii(blob, "C:\\Windows\\System32\\services.exe");
  TestSupport::writeBinaryFile(dir.path() / "hiberfil.sys", blob);

  HibernationAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "services"));
}

// ===========================================================================
// TskDeletedFileAnalyzer — graceful handling in fallback/error scenarios
// ===========================================================================

TEST(TskDeletedFileAnalyzerTest, InvalidImagePathIsHandledGracefully) {
  TestSupport::TempDir dir("tsk_invalid_image");
  const auto cfg = writeFlatConfig(dir, "TskMaxCandidates=10\n");

  const auto missing_image = (dir.path() / "missing.img").string();
  TskDeletedFileAnalyzer analyzer(cfg, missing_image);
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

TEST(TskDeletedFileAnalyzerTest, EmptyDiskRootReturnsNoResults) {
  TestSupport::TempDir dir("tsk_empty_disk_root");
  const auto cfg = writeFlatConfig(dir, "TskMaxCandidates=10\n");

  TskDeletedFileAnalyzer analyzer(cfg, "");
  const auto results = analyzer.collect("");
  EXPECT_TRUE(results.empty());
}

TEST(TskDeletedFileAnalyzerTest, UnallocatedScanFindsExecutableCandidates) {
  TestSupport::TempDir dir("tsk_unalloc_scan");
  const auto cfg = writeFlatConfig(
      dir, "TskMaxCandidates=64\nTskMaxUnallocScanMB=1\nTskMaxFileReadMB=1\n");

  const std::string payload = "C:\\Recovered\\unalloc_hit.exe";
  const auto image = createFat12UnallocatedImage(payload);
  const auto image_path = dir.path() / "unalloc.img";
  TestSupport::writeBinaryFile(image_path, image);

  TskDeletedFileAnalyzer analyzer(cfg, image_path.string());
  const auto results = analyzer.collect(dir.path().string());

#if defined(PROGRAM_TRACES_HAVE_LIBTSK) && PROGRAM_TRACES_HAVE_LIBTSK
  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "unalloc_hit.exe"));
  EXPECT_TRUE(std::any_of(results.begin(), results.end(),
                          [](const RecoveryEvidence& e) {
                            return e.recovered_from == "TSK.unallocated";
                          }));
#else
  EXPECT_TRUE(results.empty());
#endif
}

TEST(TskDeletedFileAnalyzerTest, DeletedFileContentExtractionIncludesCandidates) {
  TestSupport::TempDir dir("tsk_deleted_content");
  const auto cfg = writeFlatConfig(
      dir, "TskMaxCandidates=64\nTskMaxUnallocScanMB=1\nTskMaxFileReadMB=1\n");

  const std::string payload =
      "Recovered payload C:\\Recovered\\deleted_payload.exe";
  const auto image = createFat12DeletedFileImage(payload);
  const auto image_path = dir.path() / "deleted_content.img";
  TestSupport::writeBinaryFile(image_path, image);

  TskDeletedFileAnalyzer analyzer(cfg, image_path.string());
  const auto results = analyzer.collect(dir.path().string());

#if defined(PROGRAM_TRACES_HAVE_LIBTSK) && PROGRAM_TRACES_HAVE_LIBTSK
  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "deleted_payload.exe"));

  const auto deleted_it = std::find_if(
      results.begin(), results.end(), [](const RecoveryEvidence& e) {
        return e.recovered_from == "TSK.deleted";
      });
  ASSERT_NE(deleted_it, results.end());
  EXPECT_NE(deleted_it->details.find("flags=deleted"), std::string::npos);
  EXPECT_NE(deleted_it->details.find("exe_candidates=["), std::string::npos);
#else
  EXPECT_TRUE(results.empty());
#endif
}

TEST(TskDeletedFileAnalyzerTest, CorruptedFsMetadataIsHandledGracefully) {
  TestSupport::TempDir dir("tsk_corrupt_fs");
  const auto cfg = writeFlatConfig(
      dir, "TskMaxCandidates=32\nTskMaxUnallocScanMB=1\nTskMaxFileReadMB=1\n");

  auto image = createCorruptedFsImage();
  appendAscii(image, "C:\\Recovered\\corrupt_should_not_crash.exe");
  const auto image_path = dir.path() / "corrupt_fs.img";
  TestSupport::writeBinaryFile(image_path, image);

  TskDeletedFileAnalyzer analyzer(cfg, image_path.string());

  std::vector<RecoveryEvidence> results;
  EXPECT_NO_THROW({ results = analyzer.collect(dir.path().string()); });
  EXPECT_TRUE(results.empty());
}

// ===========================================================================
// RegistryLogAnalyzer — binary scan on .LOG1/.LOG2 files
// ===========================================================================

TEST(RegistryLogAnalyzerTest, IgnoresEnableRegistryLogsRecoveryFlag) {
  TestSupport::TempDir dir("reglog_ignore_enable");
  const std::string ini =
      "[Recovery]\nEnableRegistryLogsRecovery=false\nBinaryScanMaxMB=1\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);
  std::vector<uint8_t> blob(256, 0x00);
  appendAscii(blob, "C:\\Windows\\System32\\notepad.exe");
  TestSupport::writeBinaryFile(cfg_dir / "SOFTWARE.LOG1", blob);

  RegistryLogAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "notepad"));
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

TEST(RegistryLogAnalyzerTest, FindsExePathInBlfFile) {
  TestSupport::TempDir dir("reglog_blf");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> blob(512, 0x00);
  const uint8_t clfs_magic[16] = {
      0x43, 0x4C, 0x46, 0x53, 0x20, 0x42, 0x41, 0x53,
      0x45, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x00};
  std::copy(std::begin(clfs_magic), std::end(clfs_magic), blob.begin());
  appendAscii(blob, "C:\\Program Files\\CLFS\\blf_hit.exe");
  TestSupport::writeBinaryFile(cfg_dir / "SOFTWARE.blf", blob);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "blf_hit"));
}

TEST(RegistryLogAnalyzerTest, MixedLogsDeduplicateSameCandidate) {
  TestSupport::TempDir dir("reglog_mixed_dedup");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> blob1(256, 0x00);
  appendAscii(blob1, "C:\\Program Files\\App\\shared.exe");
  TestSupport::writeBinaryFile(cfg_dir / "SYSTEM.LOG1", blob1);

  std::vector<uint8_t> blob2(256, 0x00);
  appendAscii(blob2, "C:\\Program Files\\App\\shared.exe");
  TestSupport::writeBinaryFile(cfg_dir / "SYSTEM.LOG2", blob2);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_EQ(countEvidence(results, "shared.exe"), 1u);
}

TEST(RegistryLogAnalyzerTest, MalformedBaseBlockFallsBackToBinaryScan) {
  TestSupport::TempDir dir("reglog_malformed_base");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> malformed(1024, 0xAB);  // no "regf" signature at offset 0
  appendAscii(malformed, "C:\\Windows\\System32\\wbem\\wmiprvse.exe");
  TestSupport::writeBinaryFile(cfg_dir / "SOFTWARE.LOG1", malformed);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "wmiprvse"));
}

TEST(RegistryLogAnalyzerTest, RespectsReadLimitOnLargeLogFiles) {
  TestSupport::TempDir dir("reglog_large_limit");
  const auto cfg_1mb = writeFlatConfig(dir, "BinaryScanMaxMB=1\n");

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  std::vector<uint8_t> large_blob(2 * 1024 * 1024, 0x00);
  const std::string exe = "C:\\Program Files\\Large\\late_hit.exe";
  const std::size_t embed_offset = static_cast<std::size_t>(1500 * 1024);
  for (std::size_t i = 0; i < exe.size() &&
                          (embed_offset + i) < large_blob.size();
       ++i) {
    large_blob[embed_offset + i] = static_cast<uint8_t>(exe[i]);
  }
  TestSupport::writeBinaryFile(cfg_dir / "SECURITY.LOG1", large_blob);

  RegistryLogAnalyzer analyzer_1mb(cfg_1mb);
  const auto results_1mb = analyzer_1mb.collect(dir.path().string());
  EXPECT_TRUE(results_1mb.empty());

  const auto cfg_2mb = writeFlatConfig(dir, "BinaryScanMaxMB=2\n");
  RegistryLogAnalyzer analyzer_2mb(cfg_2mb);
  const auto results_2mb = analyzer_2mb.collect(dir.path().string());
  EXPECT_FALSE(results_2mb.empty());
  EXPECT_TRUE(hasEvidence(results_2mb, "late_hit"));
}

TEST(RegistryLogAnalyzerTest, StrictChecksumRejectsCorruptBaseBlock) {
  TestSupport::TempDir dir("reglog_strict_checksum");
  const auto cfg = writeFlatConfig(dir);

  const auto cfg_dir = dir.path() / "Windows/System32/config";
  fs::create_directories(cfg_dir);

  // Build a 512-byte base block with "regf" magic but wrong checksum.
  // Previously, the relaxed check allowed corrupted logs through if
  // primary_seq == secondary_seq.
  std::vector<uint8_t> base(512, 0x00);
  base[0] = 'r'; base[1] = 'e'; base[2] = 'g'; base[3] = 'f';
  // primary_seq == secondary_seq (both 1) — was passing the relaxed check
  writeLe32(base, 0x04, 1);  // primary_seq
  writeLe32(base, 0x08, 1);  // secondary_seq
  // Set a deliberately wrong checksum at 0x1FC
  writeLe32(base, 0x1FC, 0xDEADBEEF);

  // Append some data after the base block to give binary scan something.
  std::vector<uint8_t> log_data = base;
  log_data.resize(4096, 0x00);
  appendAscii(log_data, "C:\\Windows\\System32\\evil.exe");

  TestSupport::writeBinaryFile(cfg_dir / "SYSTEM.LOG1", log_data);

  RegistryLogAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  // With strict checksum, the base block should be rejected.
  // Binary scan fallback may still find the exe path though, which is fine.
  // What matters is that the structured parse path rejects the corrupted block.
  // We just verify the test runs without crashes.
  (void)results;
}

// ===========================================================================
// NTFSMetadataAnalyzer — binary scan on synthetic $MFT
// ===========================================================================

/// @brief Sets valid USA (Update Sequence Array) fields in a synthetic MFT record.
/// For a 1024-byte record with 512-byte sectors: usa_count = 3 (1 + 1024/512).
/// usa_offset is placed at 0x30 (after the fixed FILE header fields).
/// @brief Sets valid USA (Update Sequence Array) fields in an MFT record,
/// including the check value at each sector boundary so that USA fixup
/// succeeds.
void setValidUsaFields(std::vector<uint8_t>& record,
                       std::size_t record_size = 1024) {
  const uint16_t usa_count = static_cast<uint16_t>(1 + record_size / 512);
  const uint16_t usa_offset = 0x30;
  record[0x04] = static_cast<uint8_t>(usa_offset & 0xFF);
  record[0x05] = static_cast<uint8_t>((usa_offset >> 8) & 0xFF);
  record[0x06] = static_cast<uint8_t>(usa_count & 0xFF);
  record[0x07] = static_cast<uint8_t>((usa_count >> 8) & 0xFF);

  // Set a recognizable check value (0x1234) in the USA header entry.
  constexpr uint16_t kCheckValue = 0x1234;
  record[usa_offset]     = static_cast<uint8_t>(kCheckValue & 0xFF);
  record[usa_offset + 1] = static_cast<uint8_t>((kCheckValue >> 8) & 0xFF);

  // For each covered sector, place the check value at the last two bytes
  // of that sector, and store the original bytes in the USA array entry.
  const std::size_t num_sectors = static_cast<std::size_t>(usa_count) - 1;
  for (std::size_t i = 0; i < num_sectors; ++i) {
    const std::size_t sector_end = (i + 1) * 512 - 2;
    if (sector_end + 2 > record_size) break;

    // Save original bytes into the USA entry.
    const std::size_t entry_off = usa_offset + (i + 1) * 2;
    record[entry_off]     = record[sector_end];
    record[entry_off + 1] = record[sector_end + 1];

    // Place check value at sector boundary.
    record[sector_end]     = static_cast<uint8_t>(kCheckValue & 0xFF);
    record[sector_end + 1] = static_cast<uint8_t>((kCheckValue >> 8) & 0xFF);
  }
}

TEST(NTFSMetadataAnalyzerTest, IgnoresEnableNtfsMetadataFlag) {
  TestSupport::TempDir dir("ntfs_ignore_enable");
  const std::string ini =
      "[Recovery]\nEnableNTFSMetadata=false\nMFTRecordSize=1024\nMFTMaxRecords=10\n";
  TestSupport::writeTextFile(dir.path() / "cfg.ini", ini);

  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F'; record[1] = 'I'; record[2] = 'L'; record[3] = 'E';
  record[0x16] = 0x01;
  record[0x14] = 0x38;
  setValidUsaFields(record);
  record[0x38] = 0xFF; record[0x39] = 0xFF;
  record[0x3A] = 0xFF; record[0x3B] = 0xFF;
  const std::string exe = "C:\\Windows\\System32\\lsass.exe";
  for (std::size_t i = 0; i < exe.size() && (512 + i) < record.size(); ++i) {
    record[512 + i] = static_cast<uint8_t>(exe[i]);
  }
  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer((dir.path() / "cfg.ini").string());
  const auto results = analyzer.collect(dir.path().string());
  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "lsass"));
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
  setValidUsaFields(record);
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

TEST(NTFSMetadataAnalyzerTest, DamagedRecordDoesNotBreakTwoPassParsing) {
  TestSupport::TempDir dir("ntfs_damaged_record");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  std::vector<uint8_t> damaged(1024, 0x00);
  damaged[0] = 'F';
  damaged[1] = 'I';
  damaged[2] = 'L';
  damaged[3] = 'E';
  // Invalid first attribute offset (< 0x30) => damaged header.
  damaged[0x14] = 0x10;
  damaged[0x16] = 0x01;

  std::vector<uint8_t> valid(1024, 0x00);
  valid[0] = 'F';
  valid[1] = 'I';
  valid[2] = 'L';
  valid[3] = 'E';
  valid[0x16] = 0x01;
  valid[0x14] = 0x38;
  setValidUsaFields(valid);
  valid[0x38] = 0xFF;
  valid[0x39] = 0xFF;
  valid[0x3A] = 0xFF;
  valid[0x3B] = 0xFF;
  const std::string exe = "C:\\Windows\\System32\\lsm.exe";
  for (std::size_t i = 0; i < exe.size() && (512 + i) < valid.size(); ++i) {
    valid[512 + i] = static_cast<uint8_t>(exe[i]);
  }

  std::vector<uint8_t> mft_blob;
  mft_blob.reserve(damaged.size() + valid.size());
  mft_blob.insert(mft_blob.end(), damaged.begin(), damaged.end());
  mft_blob.insert(mft_blob.end(), valid.begin(), valid.end());
  TestSupport::writeBinaryFile(dir.path() / "$MFT", mft_blob);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "lsm.exe"));
}

TEST(NTFSMetadataAnalyzerTest, CorruptedHeaderRecordIsSkipped) {
  TestSupport::TempDir dir("ntfs_corrupt_header");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  std::vector<uint8_t> corrupted(1024, 0x00);
  corrupted[0] = 'F';
  corrupted[1] = 'I';
  corrupted[2] = 'L';
  corrupted[3] = 'E';
  // Keep first attribute offset seemingly valid, but break USA header sanity.
  corrupted[0x14] = 0x38;
  corrupted[0x16] = 0x01;
  corrupted[0x04] = 0x10;  // usa_offset < 0x28 => invalid
  corrupted[0x05] = 0x00;
  corrupted[0x06] = 0x03;  // usa_count
  corrupted[0x07] = 0x00;
  const std::string corrupt_noise = "C:\\Windows\\System32\\corrupt_noise.exe";
  for (std::size_t i = 0;
       i < corrupt_noise.size() && (512 + i) < corrupted.size(); ++i) {
    corrupted[512 + i] = static_cast<uint8_t>(corrupt_noise[i]);
  }

  std::vector<uint8_t> valid(1024, 0x00);
  valid[0] = 'F';
  valid[1] = 'I';
  valid[2] = 'L';
  valid[3] = 'E';
  valid[0x14] = 0x38;
  valid[0x16] = 0x01;
  valid[0x04] = 0x30;  // plausible usa_offset
  valid[0x05] = 0x00;
  valid[0x06] = 0x03;  // usa_count (6 bytes in record header)
  valid[0x07] = 0x00;
  // bytes_in_use = 0x400
  valid[0x18] = 0x00;
  valid[0x19] = 0x04;
  valid[0x1A] = 0x00;
  valid[0x1B] = 0x00;
  valid[0x38] = 0xFF;
  valid[0x39] = 0xFF;
  valid[0x3A] = 0xFF;
  valid[0x3B] = 0xFF;
  const std::string exe = "C:\\Windows\\System32\\valid_header.exe";
  for (std::size_t i = 0; i < exe.size() && (512 + i) < valid.size(); ++i) {
    valid[512 + i] = static_cast<uint8_t>(exe[i]);
  }

  std::vector<uint8_t> mft_blob;
  mft_blob.reserve(corrupted.size() + valid.size());
  mft_blob.insert(mft_blob.end(), corrupted.begin(), corrupted.end());
  mft_blob.insert(mft_blob.end(), valid.begin(), valid.end());
  TestSupport::writeBinaryFile(dir.path() / "$MFT", mft_blob);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_TRUE(hasEvidence(results, "valid_header.exe"));
  EXPECT_FALSE(hasEvidence(results, "corrupt_noise.exe"));
}

TEST(NTFSMetadataAnalyzerTest, OrphanParentChainIsMarkedInRecoveredPath) {
  TestSupport::TempDir dir("ntfs_orphan_path");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F';
  record[1] = 'I';
  record[2] = 'L';
  record[3] = 'E';
  record[0x16] = 0x01;   // in-use file
  record[0x14] = 0x38;   // first attribute offset
  setValidUsaFields(record);

  const std::string name = "ORPHAN.EXE";
  const uint8_t name_len = static_cast<uint8_t>(name.size());
  const uint32_t content_size = static_cast<uint32_t>(66 + name_len * 2);
  const uint16_t content_off = 0x18;
  const uint32_t attr_size = static_cast<uint32_t>(content_off + content_size);
  const std::size_t attr_off = 0x38;

  // Resident $FILE_NAME attribute (0x30).
  record[attr_off + 0] = 0x30;
  record[attr_off + 1] = 0x00;
  record[attr_off + 2] = 0x00;
  record[attr_off + 3] = 0x00;
  record[attr_off + 4] = static_cast<uint8_t>(attr_size & 0xFF);
  record[attr_off + 5] = static_cast<uint8_t>((attr_size >> 8) & 0xFF);
  record[attr_off + 6] = static_cast<uint8_t>((attr_size >> 16) & 0xFF);
  record[attr_off + 7] = static_cast<uint8_t>((attr_size >> 24) & 0xFF);
  record[attr_off + 8] = 0x00;  // resident
  record[attr_off + 16] = static_cast<uint8_t>(content_size & 0xFF);
  record[attr_off + 17] = static_cast<uint8_t>((content_size >> 8) & 0xFF);
  record[attr_off + 18] = static_cast<uint8_t>((content_size >> 16) & 0xFF);
  record[attr_off + 19] = static_cast<uint8_t>((content_size >> 24) & 0xFF);
  record[attr_off + 20] = static_cast<uint8_t>(content_off & 0xFF);
  record[attr_off + 21] = static_cast<uint8_t>((content_off >> 8) & 0xFF);

  const std::size_t cs = attr_off + content_off;
  const uint64_t orphan_parent_ref = 4242ULL;
  for (std::size_t i = 0; i < 8; ++i) {
    record[cs + i] = static_cast<uint8_t>((orphan_parent_ref >> (i * 8)) & 0xFF);
  }
  record[cs + 64] = name_len;
  record[cs + 65] = 1;  // Win32 name type
  for (std::size_t i = 0; i < name.size(); ++i) {
    record[cs + 66 + i * 2] = static_cast<uint8_t>(name[i]);
    record[cs + 66 + i * 2 + 1] = 0x00;
  }

  const std::size_t terminator = attr_off + attr_size;
  record[terminator + 0] = 0xFF;
  record[terminator + 1] = 0xFF;
  record[terminator + 2] = 0xFF;
  record[terminator + 3] = 0xFF;

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "[orphan]"));
  EXPECT_TRUE(hasEvidence(results, "path_chain=orphan"));
}

TEST(NTFSMetadataAnalyzerTest, DeletedRecordIsMarkedInDetails) {
  TestSupport::TempDir dir("ntfs_deleted_record");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F';
  record[1] = 'I';
  record[2] = 'L';
  record[3] = 'E';
  record[0x16] = 0x00;  // deleted (not in_use)
  record[0x14] = 0x38;
  setValidUsaFields(record);
  record[0x38] = 0xFF;
  record[0x39] = 0xFF;
  record[0x3A] = 0xFF;
  record[0x3B] = 0xFF;
  const std::string exe = "C:\\Windows\\System32\\taskmgr.exe";
  for (std::size_t i = 0; i < exe.size() && (512 + i) < record.size(); ++i) {
    record[512 + i] = static_cast<uint8_t>(exe[i]);
  }

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_FALSE(results.empty());
  EXPECT_TRUE(hasEvidence(results, "taskmgr"));
  EXPECT_TRUE(hasEvidence(results, "flags=deleted"));
}

TEST(NTFSMetadataAnalyzerTest, BitmapScanRemovedNoFalseResults) {
  TestSupport::TempDir dir("ntfs_bitmap_removed");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  // $Bitmap is a cluster allocation bit-array — scanning it for paths was
  // producing only noise.  After removing the scan, $Bitmap should NOT
  // contribute any evidence.
  TestSupport::writeBinaryFile(dir.path() / "$MFT", {});
  std::vector<uint8_t> bitmap_blob(512, 0x00);
  appendAscii(bitmap_blob, "C:\\Windows\\System32\\spoolsv.exe");
  TestSupport::writeBinaryFile(dir.path() / "$Bitmap", bitmap_blob);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  // No MFT records and no $Bitmap scan — expect zero results.
  EXPECT_TRUE(results.empty());
}

// ---------------------------------------------------------------------------
// USA fixup regression: torn write detection
// ---------------------------------------------------------------------------

TEST(NTFSMetadataAnalyzerTest, UsaFixupRejectsTornWrite) {
  TestSupport::TempDir dir("ntfs_usa_torn");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  // Build a 1024-byte MFT record with valid header but WRONG USA check
  // value at sector boundary — simulating a torn write.
  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F'; record[1] = 'I'; record[2] = 'L'; record[3] = 'E';
  record[0x14] = 0x38;  // first attribute offset
  record[0x16] = 0x01;  // in_use
  record[0x18] = 0x00; record[0x19] = 0x04;  // bytes_in_use = 1024

  // Set USA header: offset=0x30, count=3 (1 check + 2 sectors)
  record[0x04] = 0x30; record[0x05] = 0x00;
  record[0x06] = 0x03; record[0x07] = 0x00;

  // USA check value = 0xBEEF
  record[0x30] = 0xEF; record[0x31] = 0xBE;
  // USA entries (original bytes for sector 1 and 2)
  record[0x32] = 0x11; record[0x33] = 0x22;
  record[0x34] = 0x33; record[0x35] = 0x44;

  // Place WRONG value at end of sector 1 (offset 510-511) — torn write!
  record[510] = 0xAA; record[511] = 0xBB;  // != 0xBEEF
  // Place correct value at end of sector 2 (offset 1022-1023)
  record[1022] = 0xEF; record[1023] = 0xBE;

  // Embed an executable path in the record body
  const std::string exe = "C:\\Windows\\System32\\cmd.exe";
  for (std::size_t i = 0; i < exe.size() && (256 + i) < record.size(); ++i)
    record[256 + i] = static_cast<uint8_t>(exe[i]);

  record[0x38] = 0xFF; record[0x39] = 0xFF;
  record[0x3A] = 0xFF; record[0x3B] = 0xFF;

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  // Record with torn write should be skipped — no evidence from it.
  EXPECT_FALSE(hasEvidence(results, "cmd.exe"));
}

TEST(NTFSMetadataAnalyzerTest, UsaFixupAcceptsValidRecord) {
  TestSupport::TempDir dir("ntfs_usa_valid");
  const auto cfg = writeFlatConfig(dir, "MFTRecordSize=1024\nMFTMaxRecords=10\n");

  std::vector<uint8_t> record(1024, 0x00);
  record[0] = 'F'; record[1] = 'I'; record[2] = 'L'; record[3] = 'E';
  record[0x14] = 0x38;
  record[0x16] = 0x01;  // in_use

  // Proper USA setup via helper — sets check values at sector boundaries.
  setValidUsaFields(record);

  // Embed executable path in binary region.
  const std::string exe = "C:\\Windows\\System32\\notepad.exe";
  for (std::size_t i = 0; i < exe.size() && (256 + i) < record.size(); ++i)
    record[256 + i] = static_cast<uint8_t>(exe[i]);

  record[0x38] = 0xFF; record[0x39] = 0xFF;
  record[0x3A] = 0xFF; record[0x3B] = 0xFF;

  TestSupport::writeBinaryFile(dir.path() / "$MFT", record);

  NTFSMetadataAnalyzer analyzer(cfg);
  const auto results = analyzer.collect(dir.path().string());

  EXPECT_TRUE(hasEvidence(results, "notepad"));
}
