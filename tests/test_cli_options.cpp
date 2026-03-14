#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "infra/cli/cli_options.hpp"

namespace {

std::optional<ProgramTraces::Cli::CliOptions> parseArgs(
    std::vector<std::string> args, std::string& error_message) {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& arg : args) {
    argv.push_back(arg.data());
  }

  return ProgramTraces::Cli::parseArguments(
      static_cast<int>(argv.size()), argv.data(), error_message);
}

}  // namespace

TEST(CliOptionsTest, UsesAutoDiskRootForNamedConfigAndOutput) {
  std::string error_message;
  auto options = parseArgs({"program_traces", "-c", "config.ini", "-o", "out.csv"},
                           error_message);
  ASSERT_TRUE(options.has_value()) << error_message;
  EXPECT_EQ(options->disk_root, "auto");
  EXPECT_EQ(options->config_path, "config.ini");
  EXPECT_EQ(options->output_path, "out.csv");
}

TEST(CliOptionsTest, ParsesShortAliasesForLoggingAndRecoveryOutput) {
  std::string error_message;
  auto options = parseArgs({"program_traces", "-d", "/mnt/windows", "-c",
                            "config.ini", "-o", "out.csv", "-l", "app.log",
                            "-R", "recovery.csv"},
                           error_message);
  ASSERT_TRUE(options.has_value()) << error_message;
  EXPECT_EQ(options->disk_root, "/mnt/windows");
  EXPECT_EQ(options->log_path, "app.log");
  EXPECT_TRUE(options->export_recovery_csv);
  EXPECT_EQ(options->recovery_output_path, "recovery.csv");
}

TEST(CliOptionsTest, ShowsHelpWhenNoArgumentsProvided) {
  std::string error_message;
  auto options = parseArgs({"program_traces"}, error_message);
  ASSERT_TRUE(options.has_value()) << error_message;
  EXPECT_TRUE(options->show_help);
}

