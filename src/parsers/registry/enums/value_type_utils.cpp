#include "value_type_utils.hpp"

#include "value_type.hpp"

namespace RegistryAnalysis {

std::string valueTypeToString(RegistryValueType type) {
  switch (type) {
    case RegistryValueType::REG_NONE:
      return "REG_NONE";
    case RegistryValueType::REG_SZ:
      return "REG_SZ";
    case RegistryValueType::REG_EXPAND_SZ:
      return "REG_EXPAND_SZ";
    case RegistryValueType::REG_BINARY:
      return "REG_BINARY";
    case RegistryValueType::REG_DWORD:
      return "REG_DWORD";
    case RegistryValueType::REG_DWORD_BIG_ENDIAN:
      return "REG_DWORD_BIG_ENDIAN";
    case RegistryValueType::REG_LINK:
      return "REG_LINK";
    case RegistryValueType::REG_MULTI_SZ:
      return "REG_MULTI_SZ";
    case RegistryValueType::REG_RESOURCE_LIST:
      return "REG_RESOURCE_LIST";
    case RegistryValueType::REG_QWORD:
      return "REG_QWORD";
    default:
      return "UNKNOWN_TYPE_" + std::to_string(static_cast<uint32_t>(type));
  }
}

bool isStringType(RegistryValueType type) {
  switch (type) {
    case RegistryValueType::REG_SZ:
    case RegistryValueType::REG_EXPAND_SZ:
    case RegistryValueType::REG_LINK:
      return true;
    default:
      return false;
  }
}

bool isIntegerType(RegistryValueType type) {
  switch (type) {
    case RegistryValueType::REG_DWORD:
    case RegistryValueType::REG_DWORD_BIG_ENDIAN:
    case RegistryValueType::REG_QWORD:
      return true;
    default:
      return false;
  }
}

}
