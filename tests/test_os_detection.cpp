#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "analysis/os/os_detection.hpp"
#include "parsers/registry/data_model/idata.hpp"
#include "parsers/registry/data_model/storage/data_storage.hpp"
#include "parsers/registry/enums/value_type.hpp"
#include "test_support.hpp"

namespace {

class FakeRegistryData final : public RegistryAnalysis::IRegistryData {
 public:
  FakeRegistryData(std::string name, RegistryAnalysis::RegistryValueType type,
                   RegistryAnalysis::RegistryValueVariant value)
      : name_(std::move(name)), type_(type), value_(std::move(value)) {}

  const std::string& getName() const noexcept override { return name_; }

  RegistryAnalysis::RegistryValueType getType() const noexcept override {
    return type_;
  }

  std::string getDataAsString() const override {
    if (const auto* value = std::get_if<std::string>(&value_)) {
      return *value;
    }
    if (const auto* value = std::get_if<uint32_t>(&value_)) {
      return std::to_string(*value);
    }
    if (const auto* value = std::get_if<uint64_t>(&value_)) {
      return std::to_string(*value);
    }
    return {};
  }

  const RegistryAnalysis::RegistryValueVariant& getData() const noexcept override {
    return value_;
  }

  bool isNone() const noexcept override {
    return std::holds_alternative<std::monostate>(value_);
  }

  const std::string& getAsString() const override {
    return std::get<std::string>(value_);
  }

  const std::vector<uint8_t>& getAsBinary() const override {
    return std::get<std::vector<uint8_t>>(value_);
  }

  uint32_t getAsDword() const override { return std::get<uint32_t>(value_); }

  uint64_t getAsQword() const override { return std::get<uint64_t>(value_); }

  const std::vector<std::string>& getAsMultiString() const override {
    return std::get<std::vector<std::string>>(value_);
  }

 private:
  std::string name_;
  RegistryAnalysis::RegistryValueType type_;
  RegistryAnalysis::RegistryValueVariant value_;
};

class StubRegistryParser final : public RegistryAnalysis::IRegistryParser {
 public:
  using ValueList = std::vector<std::pair<std::string, std::string>>;

  void addKeyValues(const std::string& file_path, const std::string& key_path,
                    ValueList values) {
    key_values_[makeKey(file_path, key_path)] = std::move(values);
  }

  void addStringValue(const std::string& file_path,
                      const std::string& value_path,
                      const std::string& value) {
    specific_values_[makeKey(file_path, value_path)] =
        std::make_pair(RegistryAnalysis::RegistryValueType::REG_SZ,
                       RegistryAnalysis::RegistryValueVariant(value));
  }

  void addDwordValue(const std::string& file_path, const std::string& value_path,
                     uint32_t value) {
    specific_values_[makeKey(file_path, value_path)] =
        std::make_pair(RegistryAnalysis::RegistryValueType::REG_DWORD,
                       RegistryAnalysis::RegistryValueVariant(value));
  }

  std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> getKeyValues(
      const std::string& registry_file_path,
      const std::string& registry_key_path) override {
    std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> result;
    const auto it = key_values_.find(makeKey(registry_file_path, registry_key_path));
    if (it == key_values_.end()) {
      return result;
    }

    for (const auto& [name, value] : it->second) {
      result.push_back(std::make_unique<FakeRegistryData>(
          registry_key_path + "/" + name,
          RegistryAnalysis::RegistryValueType::REG_SZ, value));
    }
    return result;
  }

  std::unique_ptr<RegistryAnalysis::IRegistryData> getSpecificValue(
      const std::string& registry_file_path,
      const std::string& registry_value_path) override {
    const auto it =
        specific_values_.find(makeKey(registry_file_path, registry_value_path));
    if (it == specific_values_.end()) {
      return nullptr;
    }

    return std::make_unique<FakeRegistryData>(registry_value_path, it->second.first,
                                              it->second.second);
  }

  std::vector<std::string> listSubkeys(const std::string&,
                                       const std::string&) override {
    return {};
  }

 private:
  using SpecificValue =
      std::pair<RegistryAnalysis::RegistryValueType,
                RegistryAnalysis::RegistryValueVariant>;

  static std::string makeKey(const std::string& file_path,
                             const std::string& registry_path) {
    return file_path + "|" + registry_path;
  }

  std::unordered_map<std::string, ValueList> key_values_;
  std::unordered_map<std::string, SpecificValue> specific_values_;
};

std::string writeOsDetectionConfig(const TestSupport::TempDir& temp_dir) {
  const auto config_path = temp_dir.path() / "config.ini";
  std::ofstream file(config_path);
  file << "[General]\n"
       << "Versions = Windows10, Windows11, WindowsServer\n"
       << "[OSInfoRegistryPaths]\n"
       << "Default = Windows/System32/config/SOFTWARE\n"
       << "[OSInfoSystemRegistryPaths]\n"
       << "Default = Windows/System32/config/SYSTEM\n"
       << "[OSInfoHive]\n"
       << "Default = Microsoft/Windows NT/CurrentVersion\n"
       << "[OSInfoKeys]\n"
       << "Default = ProductName,InstallationType,CurrentBuild,CurrentBuildNumber,EditionID,DisplayVersion\n"
       << "[BuildMappingsClient]\n"
       << "10240 = Windows 10\n"
       << "22000 = Windows 11\n"
       << "[BuildMappingsServer]\n"
       << "20348 = Windows Server 2022\n"
       << "[OSKeywords]\n"
       << "DefaultServerKeywords = Server\n";
  file.close();
  return config_path.string();
}

}  // namespace

TEST(OSDetectionTest, ResolvesWindows11IniVersionFromBuildMappings) {
  TestSupport::TempDir temp_dir("os_detection_client");
  const std::string config_path = writeOsDetectionConfig(temp_dir);
  const std::string device_root = temp_dir.path().string() + "/";
  const std::string software_hive = device_root + "Windows/System32/config/SOFTWARE";
  const std::string system_hive = device_root + "Windows/System32/config/SYSTEM";

  auto parser = std::make_unique<StubRegistryParser>();
  parser->addKeyValues(
      software_hive, "Microsoft/Windows NT/CurrentVersion",
      {{"ProductName", "Windows 11 Pro"},
       {"InstallationType", "Client"},
       {"CurrentBuild", "22621"},
       {"EditionID", "Professional"},
       {"DisplayVersion", "23H2"}});
  parser->addStringValue(system_hive,
                         "CurrentControlSet/Control/ProductOptions/ProductType",
                         "WinNT");

  Config config(config_path, false, false);
  WindowsVersion::OSDetection detection(std::move(parser), std::move(config),
                                        device_root);

  const OSInfo info = detection.detect();
  EXPECT_EQ(info.ini_version, "Windows11");
  EXPECT_EQ(info.system_product_type, "WinNT");
  EXPECT_EQ(info.fullname_os, "Windows 11 Professional 23H2 22621");
}

TEST(OSDetectionTest, ResolvesWindowsServerFromControlSetFallback) {
  TestSupport::TempDir temp_dir("os_detection_server");
  const std::string config_path = writeOsDetectionConfig(temp_dir);
  const std::string device_root = temp_dir.path().string() + "/";
  const std::string software_hive = device_root + "Windows/System32/config/SOFTWARE";
  const std::string system_hive = device_root + "Windows/System32/config/SYSTEM";

  auto parser = std::make_unique<StubRegistryParser>();
  parser->addKeyValues(
      software_hive, "Microsoft/Windows NT/CurrentVersion",
      {{"ProductName", "Windows Server"},
       {"InstallationType", "Server"},
       {"CurrentBuild", "20348"},
       {"EditionID", "Datacenter"}});
  parser->addDwordValue(system_hive, "Select/Current", 1);
  parser->addStringValue(system_hive,
                         "ControlSet001/Control/ProductOptions/ProductType",
                         "ServerNT");

  Config config(config_path, false, false);
  WindowsVersion::OSDetection detection(std::move(parser), std::move(config),
                                        device_root);

  const OSInfo info = detection.detect();
  EXPECT_EQ(info.ini_version, "WindowsServer");
  EXPECT_EQ(info.system_product_type, "ServerNT");
  EXPECT_EQ(info.fullname_os, "Windows Server 2022 Datacenter 20348");
}
