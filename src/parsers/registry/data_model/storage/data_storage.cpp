#include "data_storage.hpp"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace RegistryAnalysis {

std::string DataToStringVisitor::operator()(const std::monostate&) const {
  return "";
}

std::string DataToStringVisitor::operator()(const std::string& s) const {
  return s;
}

std::string DataToStringVisitor::operator()(
    const std::vector<uint8_t>& data) const {
  std::string result;
  for (const auto byte : data) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", byte);
    result += buf;
    result += ' ';
  }
  if (!result.empty() && result.back() == ' ') {
    result.pop_back();
  }
  return result;
}

std::string DataToStringVisitor::operator()(const uint32_t value) const {
  return std::to_string(value);
}

std::string DataToStringVisitor::operator()(const uint64_t value) const {
  return std::to_string(value);
}

std::string DataToStringVisitor::operator()(
    const std::vector<std::string>& data) const {
  std::string result;
  for (const auto& s : data) {
    if (!result.empty()) result += "; ";
    result += s;
  }
  return result;
}

}
