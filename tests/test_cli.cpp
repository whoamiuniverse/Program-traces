#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

namespace {

std::string runCommand(const std::string& command) {
  std::array<char, 256> buffer{};
  std::string output;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"),
                                                pclose);
  if (!pipe) {
    throw std::runtime_error("popen failed");
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) !=
         nullptr) {
    output += buffer.data();
  }
  return output;
}

}  // namespace

TEST(CliIntegrationTest, HelpAndVersionReturnExpectedText) {
  const std::string binary = PROGRAM_TRACES_BINARY_PATH;

  const std::string help_output = runCommand(binary + " --help 2>&1");
  EXPECT_NE(help_output.find("Использование:"), std::string::npos);
  EXPECT_NE(help_output.find("-l, --log"), std::string::npos);
  EXPECT_NE(help_output.find("-r, --recovery-csv"), std::string::npos);
  EXPECT_NE(help_output.find("-R, --recovery-output <path>"), std::string::npos);
  EXPECT_NE(help_output.find("-d, --disk-root"), std::string::npos);
  EXPECT_NE(help_output.find("-c, --config"), std::string::npos);
  EXPECT_NE(help_output.find("-o, --output"), std::string::npos);
  EXPECT_NE(help_output.find("Режим auto:"), std::string::npos);

  const std::string version_output = runCommand(binary + " --version 2>&1");
  EXPECT_NE(version_output.find("Program traces"), std::string::npos);
  const std::string short_version_output = runCommand(binary + " -v 2>&1");
  EXPECT_NE(short_version_output.find("Program traces"), std::string::npos);
}
