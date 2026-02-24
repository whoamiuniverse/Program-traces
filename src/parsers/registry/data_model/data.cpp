#include "data.hpp"

#include "errors/registry_exception.hpp"
#include "parsers/registry/data_model/storage/data_storage.hpp"
#include "parsers/registry/enums/value_type_utils.hpp"

namespace RegistryAnalysis {
RegistryData::RegistryData(std::string name) : name_(std::move(name)) {}

RegistryData::RegistryData(std::string name, std::string data,
                           const RegistryValueType type)
    : name_(std::move(name)), data_(std::move(data)), type_(type) {
  validateType(type,
               {RegistryValueType::REG_SZ, RegistryValueType::REG_EXPAND_SZ,
                RegistryValueType::REG_LINK});
}

RegistryData::RegistryData(std::string name, std::vector<uint8_t> data,
                           const RegistryValueType type)
    : name_(std::move(name)), data_(std::move(data)), type_(type) {
  validateType(type, {RegistryValueType::REG_BINARY,
                      RegistryValueType::REG_RESOURCE_LIST});
}

RegistryData::RegistryData(std::string name, uint32_t data,
                           const RegistryValueType type)
    : name_(std::move(name)), data_(data), type_(type) {
  validateType(type, {RegistryValueType::REG_DWORD,
                      RegistryValueType::REG_DWORD_BIG_ENDIAN});
}

RegistryData::RegistryData(std::string name, uint64_t data)
    : name_(std::move(name)),
      data_(data),
      type_(RegistryValueType::REG_QWORD) {}

RegistryData::RegistryData(std::string name, std::vector<std::string> data)
    : name_(std::move(name)),
      data_(std::move(data)),
      type_(RegistryValueType::REG_MULTI_SZ) {}

const std::string& RegistryData::getName() const noexcept { return name_; }

RegistryValueType RegistryData::getType() const noexcept { return type_; }

const std::string& RegistryData::getAsString() const {
  if (const auto ptr = std::get_if<std::string>(&data_)) {
    return *ptr;
  }
  throw InvalidValueAccess("string", valueTypeToString(type_), name_);
}

const std::vector<uint8_t>& RegistryData::getAsBinary() const {
  if (const auto ptr = std::get_if<std::vector<uint8_t>>(&data_)) {
    return *ptr;
  }
  throw InvalidValueAccess("binary", valueTypeToString(type_), name_);
}

uint32_t RegistryData::getAsDword() const {
  if (const auto ptr = std::get_if<uint32_t>(&data_)) {
    return *ptr;
  }
  throw InvalidValueAccess("DWORD", valueTypeToString(type_), name_);
}

uint64_t RegistryData::getAsQword() const {
  if (const auto ptr = std::get_if<uint64_t>(&data_)) {
    return *ptr;
  }
  throw InvalidValueAccess("QWORD", valueTypeToString(type_), name_);
}

const std::vector<std::string>& RegistryData::getAsMultiString() const {
  if (const auto ptr = std::get_if<std::vector<std::string>>(&data_)) {
    return *ptr;
  }
  throw InvalidValueAccess("MULTI_SZ", valueTypeToString(type_), name_);
}

std::string RegistryData::getDataAsString() const {
  try {
    return std::visit(DataToStringVisitor{}, data_);
  } catch (const std::exception& e) {
    throw ValueConversionError(name_, e.what());
  }
}

const RegistryValueVariant& RegistryData::getData() const noexcept {
  return data_;
}

bool RegistryData::isNone() const noexcept {
  return type_ == RegistryValueType::REG_NONE;
}

void RegistryData::validateType(
    const RegistryValueType actual,
    const std::initializer_list<RegistryValueType> allowed) {
  for (const auto& t : allowed) {
    if (actual == t) return;
  }
  throw InvalidType(static_cast<uint32_t>(actual));
}

}
