#include "data_builder.hpp"

#include "parsers/registry/enums/value_type_utils.hpp"
#include "data.hpp"

namespace RegistryAnalysis {

RegistryDataBuilder::RegistryDataBuilder()
    : type_(RegistryValueType::REG_NONE) {}

RegistryDataBuilder& RegistryDataBuilder::setName(const std::string& name) {
  name_ = name;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setType(RegistryValueType type) {
  validateTypeCompatibility(type);
  type_ = type;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setString(const std::string& data) {
  data_ = data;
  type_ = RegistryValueType::REG_SZ;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setExpandString(
    const std::string& data) {
  data_ = data;
  type_ = RegistryValueType::REG_EXPAND_SZ;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setBinary(
    const std::vector<uint8_t>& data) {
  data_ = data;
  type_ = RegistryValueType::REG_BINARY;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setDword(uint32_t data) {
  data_ = data;
  type_ = RegistryValueType::REG_DWORD;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setDwordBigEndian(uint32_t data) {
  data_ = data;
  type_ = RegistryValueType::REG_DWORD_BIG_ENDIAN;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setQword(uint64_t data) {
  data_ = data;
  type_ = RegistryValueType::REG_QWORD;
  return *this;
}

RegistryDataBuilder& RegistryDataBuilder::setMultiString(
    const std::vector<std::string>& data) {
  data_ = data;
  type_ = RegistryValueType::REG_MULTI_SZ;
  return *this;
}

std::unique_ptr<IRegistryData> RegistryDataBuilder::build() const {
  switch (type_) {
    case RegistryValueType::REG_NONE:
      return std::make_unique<RegistryData>(name_);

    case RegistryValueType::REG_SZ:
    case RegistryValueType::REG_EXPAND_SZ:
    case RegistryValueType::REG_LINK:
      return std::make_unique<RegistryData>(name_, std::get<std::string>(data_),
                                            type_);

    case RegistryValueType::REG_BINARY:
    case RegistryValueType::REG_RESOURCE_LIST:
      return std::make_unique<RegistryData>(
          name_, std::get<std::vector<uint8_t>>(data_), type_);

    case RegistryValueType::REG_DWORD:
    case RegistryValueType::REG_DWORD_BIG_ENDIAN:
      return std::make_unique<RegistryData>(name_, std::get<uint32_t>(data_),
                                            type_);

    case RegistryValueType::REG_QWORD:
      return std::make_unique<RegistryData>(name_, std::get<uint64_t>(data_));

    case RegistryValueType::REG_MULTI_SZ:
      return std::make_unique<RegistryData>(
          name_, std::get<std::vector<std::string>>(data_));

    default:
      throw UnsupportedTypeError(static_cast<uint32_t>(type_));
  }
}

void RegistryDataBuilder::validateTypeCompatibility(
    const RegistryValueType type) const {
  const auto current_index = data_.index();
  const bool is_compatible = [&] {
    switch (type) {
      case RegistryValueType::REG_NONE:
        return current_index == 0;  // monostate
      case RegistryValueType::REG_SZ:
      case RegistryValueType::REG_EXPAND_SZ:
      case RegistryValueType::REG_LINK:
        return current_index == 1;  // string
      case RegistryValueType::REG_BINARY:
      case RegistryValueType::REG_RESOURCE_LIST:
        return current_index == 2;  // binary
      case RegistryValueType::REG_DWORD:
      case RegistryValueType::REG_DWORD_BIG_ENDIAN:
        return current_index == 3;  // uint32_t
      case RegistryValueType::REG_QWORD:
        return current_index == 4;  // uint64_t
      case RegistryValueType::REG_MULTI_SZ:
        return current_index == 5;  // vector<string>
      default:
        return false;
    }
  }();

  if (!is_compatible) {
    throw TypeCompatibilityError(valueTypeToString(type),
                                 valueTypeToString(type_), name_);
  }
}

}
