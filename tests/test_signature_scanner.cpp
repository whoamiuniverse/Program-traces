/// @file test_signature_scanner.cpp
/// @brief Unit tests for SignatureScanner and SignatureDatabase.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/recovery/signature/signature_database.hpp"
#include "analysis/artifacts/recovery/signature/signature_scanner.hpp"
#include "test_support.hpp"

using namespace WindowsDiskAnalysis;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// @brief Builds a byte blob with the given signature bytes embedded at @p offset.
std::vector<uint8_t> makeBlobWithSig(const uint8_t* sig_bytes, std::size_t sig_len,
                                      std::size_t embed_offset, std::size_t total_size) {
  std::vector<uint8_t> blob(total_size, 0x00);
  for (std::size_t i = 0; i < sig_len && (embed_offset + i) < total_size; ++i) {
    blob[embed_offset + i] = sig_bytes[i];
  }
  return blob;
}

/// @brief Builds a minimal EVTX blob: ElfFile\0\0 at offset 0.
std::vector<uint8_t> makeEvtxBlob() {
  auto blob = makeBlobWithSig(SignatureDB::kSigEvtx.data(),
                               SignatureDB::kSigEvtx.size(), 0, 8192);
  return blob;
}

/// @brief Builds a minimal LNK blob: HeaderSize=0x4C, CLSID bytes at 0.
std::vector<uint8_t> makeLnkBlob() {
  // kSigLnk = { 0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00 }
  auto blob = makeBlobWithSig(SignatureDB::kSigLnk.data(),
                               SignatureDB::kSigLnk.size(), 0, 256);
  return blob;
}

/// @brief Builds a minimal PE blob: MZ magic + valid PE offset at 0x3C.
std::vector<uint8_t> makePeBlob() {
  std::vector<uint8_t> blob(4096, 0x00);
  blob[0] = 0x4D;  // M
  blob[1] = 0x5A;  // Z
  // PE offset at 0x3C = 0x80 (128), sane value < 4096
  blob[0x3C] = 0x80;
  blob[0x3D] = 0x00;
  blob[0x3E] = 0x00;
  blob[0x3F] = 0x00;
  return blob;
}

/// @brief Builds a Prefetch SCCA blob: "SCCA" + version byte 0x1E (Win10).
std::vector<uint8_t> makePrefetchBlob() {
  std::vector<uint8_t> blob(2048, 0x00);
  // kSigPrefetchScca = { 0x53,0x43,0x43,0x41 } = "SCCA"
  blob[0] = 0x53; blob[1] = 0x43; blob[2] = 0x43; blob[3] = 0x41;
  blob[4] = 0x1E;  // version v30 (Win10) — passes validatePrefetch
  return blob;
}

/// @brief Creates a temporary binary file and returns its path.
std::string writeTempBinary(const TestSupport::TempDir& dir,
                             const std::string& filename,
                             const std::vector<uint8_t>& bytes) {
  const auto path = dir.path() / filename;
  TestSupport::writeBinaryFile(path, bytes);
  return path.string();
}

/// @brief Creates a minimal config INI with the given image_path.
std::string writeTempConfig(const TestSupport::TempDir& dir,
                             const std::string& image_path = "") {
  std::string ini = "[Recovery]\nEnableSignatureScan=true\n";
  if (!image_path.empty()) {
    ini += "SignatureScanPath=" + image_path + "\n";
  }
  const auto path = dir.path() / "config.ini";
  TestSupport::writeTextFile(path, ini);
  return path.string();
}

}  // namespace

// ---------------------------------------------------------------------------
// SignatureDatabase tests
// ---------------------------------------------------------------------------

TEST(SignatureDatabaseTest, ContainsExpectedArtifactCount) {
  EXPECT_EQ(SignatureDB::kSignatures.size(), 9u);
}

TEST(SignatureDatabaseTest, EvtxSignatureIsEightBytes) {
  const auto& sig = SignatureDB::kSignatures[0];
  EXPECT_EQ(std::string_view(sig.artifact_type), "EVTX");
  EXPECT_EQ(sig.byte_count, 8u);
  EXPECT_EQ(sig.file_offset, 0u);
}

TEST(SignatureDatabaseTest, EseSignatureHasFileOffset4) {
  // ESE/JET signature sits at offset 4 in the file
  const auto* ese_sig = [&]() -> const ArtifactSignature* {
    for (const auto& s : SignatureDB::kSignatures) {
      if (s.artifact_type == "ESE/JET") return &s;
    }
    return nullptr;
  }();
  ASSERT_NE(ese_sig, nullptr);
  EXPECT_EQ(ese_sig->file_offset, 4u);
}

TEST(SignatureDatabaseTest, PeSignatureIsTwoBytes) {
  const auto& sig = SignatureDB::kSignatures.back();
  EXPECT_EQ(std::string_view(sig.artifact_type), "PE");
  EXPECT_EQ(sig.byte_count, 2u);
}

TEST(SignatureDatabaseTest, AllSignaturesHaveNonNullBytes) {
  for (const auto& sig : SignatureDB::kSignatures) {
    EXPECT_NE(sig.bytes, nullptr) << sig.artifact_type;
    EXPECT_GT(sig.byte_count, 0u) << sig.artifact_type;
  }
}

// ---------------------------------------------------------------------------
// SignatureScanner — disabled scanner returns empty
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DisabledScannerReturnsEmpty) {
  TestSupport::TempDir dir("sig_disabled");
  const std::string cfg = writeTempConfig(dir);
  // Override enable flag in config
  const std::string ini_content = "[Recovery]\nEnableSignatureScan=false\n";
  TestSupport::writeTextFile(dir.path() / "config.ini", ini_content);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

// ---------------------------------------------------------------------------
// SignatureScanner — detects EVTX in explicit image
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DetectsEvtxInExplicitImageFile) {
  TestSupport::TempDir dir("sig_evtx");
  const auto blob = makeEvtxBlob();
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  ASSERT_FALSE(results.empty());
  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("EVTX") != std::string::npos;
      });
  EXPECT_TRUE(found) << "Expected at least one EVTX hit";
}

// ---------------------------------------------------------------------------
// SignatureScanner — detects LNK in explicit image
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DetectsLnkInExplicitImageFile) {
  TestSupport::TempDir dir("sig_lnk");
  const auto blob  = makeLnkBlob();
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("LNK") != std::string::npos;
      });
  EXPECT_TRUE(found) << "Expected at least one LNK hit";
}

// ---------------------------------------------------------------------------
// SignatureScanner — detects PE (with valid PE offset) in image
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DetectsPeWithValidOffsetInImageFile) {
  TestSupport::TempDir dir("sig_pe");
  const auto blob  = makePeBlob();
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("PE") != std::string::npos;
      });
  EXPECT_TRUE(found) << "Expected at least one PE hit";
}

// ---------------------------------------------------------------------------
// SignatureScanner — invalid PE offset (>= 4096) is rejected
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, RejectsPeWithInvalidOffset) {
  TestSupport::TempDir dir("sig_pe_invalid");
  std::vector<uint8_t> blob(4096, 0x00);
  blob[0] = 0x4D;  // MZ
  blob[1] = 0x5A;
  // PE offset = 0xFFFF (65535) — exceeds 4096, must be rejected
  blob[0x3C] = 0xFF;
  blob[0x3D] = 0xFF;
  blob[0x3E] = 0x00;
  blob[0x3F] = 0x00;
  const auto image = writeTempBinary(dir, "bad_pe.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("PE") != std::string::npos;
      });
  EXPECT_FALSE(found) << "PE with offset >= 4096 must be rejected";
}

// ---------------------------------------------------------------------------
// SignatureScanner — detects Prefetch SCCA with valid version byte
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DetectsPrefetchWithValidVersionByte) {
  TestSupport::TempDir dir("sig_pf");
  const auto blob  = makePrefetchBlob();
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("Prefetch") != std::string::npos;
      });
  EXPECT_TRUE(found) << "Expected Prefetch with version 0x1E to be detected";
}

// ---------------------------------------------------------------------------
// SignatureScanner — Prefetch with unknown version byte is rejected
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, RejectsPrefetchWithUnknownVersionByte) {
  TestSupport::TempDir dir("sig_pf_bad");
  std::vector<uint8_t> blob(2048, 0x00);
  blob[0] = 0x53; blob[1] = 0x43; blob[2] = 0x43; blob[3] = 0x41;
  blob[4] = 0xFF;  // Unknown version byte — must be rejected
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("Prefetch") != std::string::npos;
      });
  EXPECT_FALSE(found) << "Prefetch with unknown version must be rejected";
}

// ---------------------------------------------------------------------------
// SignatureScanner — CLI override takes precedence over config
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, CliImagePathOverridesConfig) {
  TestSupport::TempDir dir("sig_override");
  // Config points to a non-existent file
  const auto cfg = writeTempConfig(dir, "/nonexistent/image.img");
  // CLI override points to a real EVTX blob
  const auto blob  = makeEvtxBlob();
  const auto image = writeTempBinary(dir, "override.img", blob);

  SignatureScanner scanner(cfg, image);  // CLI override
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("EVTX") != std::string::npos;
      });
  EXPECT_TRUE(found) << "CLI image_path override should be used instead of config value";
}

// ---------------------------------------------------------------------------
// SignatureScanner — pagefile.sys scan
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, DetectsEvtxInPagefile) {
  TestSupport::TempDir dir("sig_pagefile");
  // No explicit image in config — scanner falls back to pagefile.sys
  const std::string ini = "[Recovery]\nEnableSignatureScan=true\nSignatureScanPagefile=true\n";
  TestSupport::writeTextFile(dir.path() / "config.ini", ini);

  // Place pagefile.sys with embedded EVTX signature
  const auto blob = makeEvtxBlob();
  TestSupport::writeBinaryFile(dir.path() / "pagefile.sys", blob);

  SignatureScanner scanner((dir.path() / "config.ini").string());
  const auto results = scanner.collect(dir.path().string());

  const bool found = std::any_of(results.begin(), results.end(),
      [](const RecoveryEvidence& ev) {
        return ev.executable_path.find("EVTX") != std::string::npos;
      });
  EXPECT_TRUE(found) << "EVTX must be found in pagefile.sys";
}

// ---------------------------------------------------------------------------
// SignatureScanner — empty image produces no results
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, EmptyImageProducesNoResults) {
  TestSupport::TempDir dir("sig_empty");
  const auto image = writeTempBinary(dir, "empty.img", {});
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());
  EXPECT_TRUE(results.empty());
}

// ---------------------------------------------------------------------------
// SignatureScanner — evidence fields are properly populated
// ---------------------------------------------------------------------------

TEST(SignatureScannerTest, EvidenceFieldsArePopulated) {
  TestSupport::TempDir dir("sig_fields");
  const auto blob  = makeEvtxBlob();
  const auto image = writeTempBinary(dir, "disk.img", blob);
  const auto cfg   = writeTempConfig(dir, image);

  SignatureScanner scanner(cfg);
  const auto results = scanner.collect(dir.path().string());
  ASSERT_FALSE(results.empty());

  for (const auto& ev : results) {
    EXPECT_FALSE(ev.executable_path.empty());
    EXPECT_FALSE(ev.source.empty());
    EXPECT_FALSE(ev.recovered_from.empty());
    EXPECT_FALSE(ev.details.empty());
  }
}
