/// @file test_recovery_contract.cpp
/// @brief Regression tests for canonical recovery source/recovered_from contract.

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/data/recovery_contract.hpp"

using namespace WindowsDiskAnalysis;

TEST(RecoveryContractTest, CanonicalSourceDictionaryIsStable) {
  const auto& sources = RecoveryContract::kCanonicalSources;
  ASSERT_EQ(sources.size(), 7u);
  EXPECT_EQ(sources[0], "USN");
  EXPECT_EQ(sources[1], "VSS");
  EXPECT_EQ(sources[2], "Hiber");
  EXPECT_EQ(sources[3], "NTFSMetadata");
  EXPECT_EQ(sources[4], "RegistryLog");
  EXPECT_EQ(sources[5], "SignatureScan");
  EXPECT_EQ(sources[6], "TSK");
}

TEST(RecoveryContractTest, CanonicalizesLegacyMarkersAcrossAllRecoveryModules) {
  struct Case {
    std::string source;
    std::string recovered_from;
    std::string expected_source;
    std::string expected_recovered_from;
  };

  const std::vector<Case> cases = {
      {.source = "USN",
       .recovered_from = "USN(binary)",
       .expected_source = "USN",
       .expected_recovered_from = "USN.binary"},
      {.source = "$LogFile",
       .recovered_from = "$LogFile",
       .expected_source = "USN",
       .expected_recovered_from = "USN.logfile_binary"},
      {.source = "Pagefile",
       .recovered_from = "Pagefile",
       .expected_source = "VSS",
       .expected_recovered_from = "VSS.pagefile_binary"},
      {.source = "Memory",
       .recovered_from = "Hiber(TCPEndpoint)",
       .expected_source = "Hiber",
       .expected_recovered_from = "Hiber.tcp_endpoint"},
      {.source = "NTFSMetadata",
       .recovered_from = "$Bitmap(binary)",
       .expected_source = "NTFSMetadata",
       .expected_recovered_from = "NTFSMetadata.bitmap_binary"},
      {.source = "Registry",
       .recovered_from = "RegistryLog(SYSTEM.LOG2)(HvLE_dirty_page)",
       .expected_source = "RegistryLog",
       .expected_recovered_from = "RegistryLog.hvle_dirty_page"},
      {.source = "SignatureScan",
       .recovered_from = "Signature",
       .expected_source = "SignatureScan",
       .expected_recovered_from = "SignatureScan.signature"},
      {.source = "TSK",
       .recovered_from = "TSK(unallocated)",
       .expected_source = "TSK",
       .expected_recovered_from = "TSK.unallocated"},
  };

  for (const auto& test_case : cases) {
    RecoveryEvidence evidence;
    evidence.executable_path = R"(C:\Tools\sample.exe)";
    evidence.source = test_case.source;
    evidence.recovered_from = test_case.recovered_from;

    RecoveryContract::canonicalizeRecoveryEvidence(evidence);

    EXPECT_EQ(evidence.source, test_case.expected_source);
    EXPECT_EQ(evidence.recovered_from, test_case.expected_recovered_from);
    EXPECT_TRUE(RecoveryContract::isCanonicalRecoverySource(evidence.source));
    EXPECT_TRUE(RecoveryContract::isCanonicalRecoveredFrom(
        evidence.source, evidence.recovered_from));
  }
}

TEST(RecoveryContractTest, EnsuresRecoveredFromIsNeverEmptyAfterCanonicalization) {
  RecoveryEvidence evidence;
  evidence.executable_path = R"(C:\Tools\empty_marker.exe)";
  evidence.source = "TSK";
  evidence.recovered_from = "";

  RecoveryContract::canonicalizeRecoveryEvidence(evidence);

  EXPECT_EQ(evidence.source, "TSK");
  EXPECT_FALSE(evidence.recovered_from.empty());
  EXPECT_EQ(evidence.recovered_from, "TSK.unknown");
}

TEST(RecoveryContractTest, EmptySourceDefaultsToUnknownNotUSN) {
  // Previously empty source + no recognized keywords silently defaulted
  // to "USN", hiding caller bugs.  Now it should return "Unknown".
  const std::string result =
      RecoveryContract::canonicalizeRecoverySource("", "");
  EXPECT_EQ(result, "Unknown");
}

TEST(RecoveryContractTest, EndpointInRecoveredFromDoesNotTriggerHiber) {
  // "endpoint" alone in recovered_from should NOT trigger Hiber source.
  // It should only do so when combined with "hiber" in source.
  const std::string result =
      RecoveryContract::canonicalizeRecoverySource("VSS", "snapshot_replay_endpoint");
  EXPECT_EQ(result, "VSS");
}

TEST(RecoveryContractTest, VectorCanonicalizationProcessesAllEntries) {
  std::vector<RecoveryEvidence> evidence(3);
  evidence[0].source = "USN";
  evidence[0].recovered_from = "USN(native)";
  evidence[1].source = "TSK";
  evidence[1].recovered_from = "TSK(deleted)";
  evidence[2].source = "";
  evidence[2].recovered_from = "";

  RecoveryContract::canonicalizeRecoveryEvidence(evidence);

  EXPECT_EQ(evidence[0].recovered_from, "USN.native");
  EXPECT_EQ(evidence[1].recovered_from, "TSK.deleted");
  EXPECT_EQ(evidence[2].source, "Unknown");
}
