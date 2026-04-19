#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>

#include <gtest/gtest.h>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "infra/export/csv_exporter.hpp"
#include "test_support.hpp"

namespace {

std::string readTextFile(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(file),
                     std::istreambuf_iterator<char>());
}

}  // namespace

TEST(CSVExporterTest, EscapesFieldsAndWritesRecoveryCsv) {
  TestSupport::TempDir temp_dir("csv_export");
  const auto output_path = temp_dir.path() / "result.csv";

  std::vector<WindowsDiskAnalysis::AutorunEntry> autorun_entries = {{
      .name = "Updater",
      .path = R"(C:\Program Files\Test App\app.exe)",
      .command = R"("C:\Program Files\Test App\app.exe" --flag)",
      .location = "Run",
  }};

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Program Files\Test App\app.exe)";
  process_info.run_times = {"2026-03-13 10:00:00"};
  process_info.timeline_artifacts = {R"([Test] value "quoted"; line
break)"};
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Program Files\Test App\app.exe)", process_info}};

  std::vector<WindowsDiskAnalysis::AmcacheEntry> amcache_entries = {{
      .file_path = R"(C:\Program Files\Test App\app.exe)",
      .name = "app.exe",
      .version = R"(1.0 "beta")",
      .source = "Amcache(BCF)",
      .modification_time_str = "2026-03-13 10:00:01",
  }};

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Program Files\Test App\app.exe)",
      .source = "NTFSMetadata",
      .recovered_from = "$MFT(binary)",
      .timestamp = "2026-03-13 10:00:02",
      .details = "details with \"quotes\"\nand newline",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(
      output_path.string(), autorun_entries, process_data, {}, amcache_entries,
      recovery_evidence, {.export_recovery_csv = true});

  const std::string main_csv = readTextFile(output_path);
  const std::string recovery_csv =
      readTextFile(temp_dir.path() / "result_recovery.csv");

  EXPECT_NE(main_csv.find("record_id;source;artifact_type;path_or_key"),
            std::string::npos);
  EXPECT_NE(main_csv.find("\"rec-1\";"), std::string::npos);
  EXPECT_NE(main_csv.find("Autorun"), std::string::npos);
  EXPECT_NE(main_csv.find("EventLog"), std::string::npos);
  EXPECT_NE(main_csv.find("Amcache"), std::string::npos);
  EXPECT_NE(main_csv.find("NTFSMetadata"), std::string::npos);
  EXPECT_NE(main_csv.find("recovery_evidence"), std::string::npos);
  EXPECT_NE(main_csv.find("version=1.0 \"\"beta\"\""), std::string::npos);
  EXPECT_NE(main_csv.find("line break"), std::string::npos);

  EXPECT_NE(recovery_csv.find("ExecutablePath;Source;RecoveredFrom;Timestamp;Details"),
            std::string::npos);
  EXPECT_NE(recovery_csv.find("details with \"\"quotes\"\" and newline"),
            std::string::npos);
}

TEST(CSVExporterTest, DoesNotWriteRecoveryCsvByDefault) {
  TestSupport::TempDir temp_dir("csv_export_no_recovery");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, {}, {},
                                                {}, {});

  EXPECT_TRUE(std::filesystem::exists(output_path));
  EXPECT_FALSE(std::filesystem::exists(temp_dir.path() / "result_recovery.csv"));
}

TEST(CSVExporterTest, WritesExpectedSourceForSingleRecord) {
  TestSupport::TempDir temp_dir("csv_export_source");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\only.exe)";
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\only.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(main_csv.find("\"rec-1\";\"EventLog\";\"eventlog_execution\""),
            std::string::npos);
}

TEST(CSVExporterTest, WritesExpectedPathOrKeyForSingleRecord) {
  TestSupport::TempDir temp_dir("csv_export_path_or_key");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\pathkey.exe)";
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\pathkey.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(
      main_csv.find("\"rec-1\";\"EventLog\";\"eventlog_execution\";\"C:\\Tools\\pathkey.exe\";"),
      std::string::npos);
}

TEST(CSVExporterTest, WritesExpectedTimestampUtcForSingleRecord) {
  TestSupport::TempDir temp_dir("csv_export_timestamp");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\time.exe)";
  process_info.evidence_sources = {"EventLog"};
  process_info.run_times = {"2026-04-08 10:11:12"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\time.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(
      main_csv.find(
          "\"rec-1\";\"EventLog\";\"eventlog_execution\";\"C:\\Tools\\time.exe\";\"2026-04-08 10:11:12\";"),
      std::string::npos);
}

TEST(CSVExporterTest, WritesExpectedIsRecoveredForExtractionAndRecovery) {
  TestSupport::TempDir temp_dir("csv_export_is_recovered");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\flag.exe)";
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\flag.exe)", process_info}};

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Tools\flag.exe)",
      .source = "NTFSMetadata",
      .recovered_from = "$MFT(binary)",
      .timestamp = "2026-04-08 10:20:00",
      .details = "deleted record",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, recovery_evidence);

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(main_csv.find("\"eventlog_execution\";\"C:\\Tools\\flag.exe\";;\"0\";"),
            std::string::npos);
  EXPECT_NE(
      main_csv.find(
          "\"recovery_evidence\";\"C:\\Tools\\flag.exe\";\"2026-04-08 10:20:00\";\"1\";"),
      std::string::npos);
}

TEST(CSVExporterTest, WritesExpectedRecoveredFromForRecoveryRecord) {
  TestSupport::TempDir temp_dir("csv_export_recovered_from");
  const auto output_path = temp_dir.path() / "result.csv";

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Tools\rf.exe)",
      .source = "NTFSMetadata",
      .recovered_from = "$MFT(binary)",
      .timestamp = "2026-04-08 10:30:00",
      .details = "deleted record",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, {}, {},
                                                {}, recovery_evidence);

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(
      main_csv.find(
          "\"rec-1\";\"NTFSMetadata\";\"recovery_evidence\";\"C:\\Tools\\rf.exe\";\"2026-04-08 10:30:00\";\"1\";\"NTFSMetadata.mft_binary\";"),
      std::string::npos);
}

TEST(CSVExporterTest, CanonicalizesLegacyRecoveryContractValues) {
  TestSupport::TempDir temp_dir("csv_export_recovery_contract");
  const auto output_path = temp_dir.path() / "result.csv";

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Tools\legacy_registry.exe)",
      .source = "Registry",
      .recovered_from = "RegistryLog(SOFTWARE.LOG1)(dirty_sector)",
      .timestamp = "2026-04-08 10:31:00",
      .details = "legacy marker",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, {}, {},
                                                {}, recovery_evidence);

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(main_csv.find("\"RegistryLog\";\"recovery_evidence\""),
            std::string::npos);
  EXPECT_NE(main_csv.find("\"RegistryLog.dirty_sector\""), std::string::npos);
}

TEST(CSVExporterTest, EnsuresRecoveredFromIsAlwaysPresentForRecoveryRows) {
  TestSupport::TempDir temp_dir("csv_export_recovery_non_empty_marker");
  const auto output_path = temp_dir.path() / "result.csv";

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Tools\no_marker.exe)",
      .source = "TSK",
      .recovered_from = "",
      .timestamp = "2026-04-08 10:32:00",
      .details = "missing recovered_from",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, {}, {},
                                                {}, recovery_evidence,
                                                {.export_recovery_csv = true});

  const std::string main_csv = readTextFile(output_path);
  const std::string recovery_csv =
      readTextFile(temp_dir.path() / "result_recovery.csv");
  EXPECT_NE(main_csv.find("\"TSK.unknown\""), std::string::npos);
  EXPECT_NE(recovery_csv.find("TSK.unknown"), std::string::npos);
}

TEST(CSVExporterTest, WritesStableSchemaHeaders) {
  TestSupport::TempDir temp_dir("csv_export_schema_headers");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::CSVExporter::exportToCSV(
      output_path.string(), {}, {}, {}, {}, {},
      {.export_recovery_csv = true});

  const std::string main_csv = readTextFile(output_path);
  const std::string recovery_csv =
      readTextFile(temp_dir.path() / "result_recovery.csv");

  EXPECT_NE(main_csv.find(
                "record_id;source;artifact_type;path_or_key;timestamp_utc;is_recovered;recovered_from;host_hint;user_hint;raw_details"),
            std::string::npos);
  EXPECT_NE(recovery_csv.find(
                "ExecutablePath;Source;RecoveredFrom;Timestamp;Details"),
            std::string::npos);
}

TEST(CSVExporterTest, RecoveryCsvRowsAreSortedAndDeduplicated) {
  TestSupport::TempDir temp_dir("csv_export_recovery_order");
  const auto output_path = temp_dir.path() / "result.csv";

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {
      {.executable_path = R"(C:\Tools\b.exe)",
       .source = "NTFSMetadata",
       .recovered_from = "NTFSMetadata.mft_binary",
       .timestamp = "2026-04-08 12:00:00",
       .details = "z"},
      {.executable_path = R"(C:\Tools\a.exe)",
       .source = "NTFSMetadata",
       .recovered_from = "NTFSMetadata.mft_binary",
       .timestamp = "2026-04-08 11:59:00",
       .details = "a"},
      {.executable_path = R"(C:\Tools\a.exe)",
       .source = "NTFSMetadata",
       .recovered_from = "NTFSMetadata.mft_binary",
       .timestamp = "2026-04-08 11:59:00",
       .details = "a"},
  };

  WindowsDiskAnalysis::CSVExporter::exportToCSV(
      output_path.string(), {}, {}, {}, {}, recovery_evidence,
      {.export_recovery_csv = true});

  const std::string recovery_csv =
      readTextFile(temp_dir.path() / "result_recovery.csv");
  const std::size_t pos_a = recovery_csv.find(R"(C:\Tools\a.exe)");
  const std::size_t pos_b = recovery_csv.find(R"(C:\Tools\b.exe)");
  ASSERT_NE(pos_a, std::string::npos);
  ASSERT_NE(pos_b, std::string::npos);
  EXPECT_LT(pos_a, pos_b);

  const std::size_t first_a = recovery_csv.find(R"(C:\Tools\a.exe)");
  const std::size_t second_a = recovery_csv.find(R"(C:\Tools\a.exe)", first_a + 1);
  EXPECT_EQ(second_a, std::string::npos);
}

TEST(CSVExporterTest, WritesHostHintWhenUncPathIsAvailable) {
  TestSupport::TempDir temp_dir("csv_export_host_hint");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(\\HOST01\Share\tool.exe)";
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(\\HOST01\Share\tool.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(main_csv.find(";\"HOST01\";;\"run_count=0"),
            std::string::npos);
}

TEST(CSVExporterTest, WritesUserHintWhenUsersAvailable) {
  TestSupport::TempDir temp_dir("csv_export_user_hint");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\user.exe)";
  process_info.evidence_sources = {"EventLog"};
  process_info.run_times = {"2026-04-08 11:00:00"};
  process_info.users = {"bob", "alice"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\user.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(
      main_csv.find(
          "\"rec-1\";\"EventLog\";\"eventlog_execution\";\"C:\\Tools\\user.exe\";\"2026-04-08 11:00:00\";\"0\";;;\"alice | bob\";"),
      std::string::npos);
}

TEST(CSVExporterTest, WritesRawDetailsForSingleRecord) {
  TestSupport::TempDir temp_dir("csv_export_raw_details");
  const auto output_path = temp_dir.path() / "result.csv";

  WindowsDiskAnalysis::ProcessInfo process_info;
  process_info.filename = R"(C:\Tools\raw.exe)";
  process_info.evidence_sources = {"EventLog"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Tools\raw.exe)", process_info}};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(output_path.string(), {}, process_data,
                                                {}, {}, {});

  const std::string main_csv = readTextFile(output_path);
  EXPECT_NE(main_csv.find(";\"run_count=0 | evidence_source=EventLog\""),
            std::string::npos);
}
