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
  process_info.tamper_flags = {"shimcache_no_exec_flag"};

  std::unordered_map<std::string, WindowsDiskAnalysis::ProcessInfo> process_data = {
      {R"(C:\Program Files\Test App\app.exe)", process_info}};

  std::vector<WindowsDiskAnalysis::AmcacheEntry> amcache_entries = {{
      .file_path = R"(C:\Program Files\Test App\app.exe)",
      .name = "app.exe",
      .version = R"(1.0 "beta")",
      .modification_time_str = "2026-03-13 10:00:01",
      .source = "Amcache(BCF)",
  }};

  std::vector<WindowsDiskAnalysis::RecoveryEvidence> recovery_evidence = {{
      .executable_path = R"(C:\Program Files\Test App\app.exe)",
      .source = "NTFSMetadata",
      .recovered_from = "$MFT(binary)",
      .timestamp = "2026-03-13 10:00:02",
      .details = "details with \"quotes\"\nand newline",
      .tamper_flag = "mft_si_fn_divergence",
  }};

  WindowsDiskAnalysis::CSVExporter::exportToCSV(
      output_path.string(), autorun_entries, process_data, {}, amcache_entries,
      recovery_evidence, {.export_recovery_csv = true});

  const std::string main_csv = readTextFile(output_path);
  const std::string recovery_csv =
      readTextFile(temp_dir.path() / "result_recovery.csv");

  EXPECT_NE(main_csv.find("Amcache(BCF)"), std::string::npos);
  EXPECT_NE(main_csv.find("\"1.0 \"\"beta\"\"\""), std::string::npos);
  EXPECT_NE(main_csv.find("quoted"), std::string::npos);

  EXPECT_NE(recovery_csv.find("mft_si_fn_divergence"), std::string::npos);
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
