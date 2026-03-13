/// @file execution_evidence_ese.cpp
/// @brief Optional libesedb-backed helpers for ExecutionEvidenceDetail.

#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

#include "common/utils.hpp"

namespace WindowsDiskAnalysis::ExecutionEvidenceDetail {

#if defined(PROGRAM_TRACES_HAVE_LIBESEDB) && PROGRAM_TRACES_HAVE_LIBESEDB

std::string toLibesedbErrorMessage(libesedb_error_t* error) {
  if (error == nullptr) {
    return "неизвестная ошибка libesedb";
  }

  std::array<char, 2048> buffer{};
  if (libesedb_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libesedb";
}

std::string sanitizeUtf8Value(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
  trim(value);
  return value;
}

std::optional<std::string> readRecordColumnNameUtf8(libesedb_record_t* record,
                                                    const int value_entry) {
  size_t name_size = 0;
  if (libesedb_record_get_utf8_column_name_size(record, value_entry, &name_size,
                                                nullptr) != 1 ||
      name_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_record_get_utf8_column_name(record, value_entry, buffer.data(),
                                           name_size, nullptr) != 1) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) {
    return std::nullopt;
  }
  return value;
}

std::optional<std::string> readRecordValueUtf8(libesedb_record_t* record,
                                               const int value_entry) {
  size_t utf8_size = 0;
  const int size_result = libesedb_record_get_value_utf8_string_size(
      record, value_entry, &utf8_size, nullptr);
  if (size_result <= 0 || utf8_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer(utf8_size);
  if (libesedb_record_get_value_utf8_string(record, value_entry, buffer.data(),
                                            utf8_size, nullptr) <= 0) {
    return std::nullopt;
  }

  std::string value(reinterpret_cast<char*>(buffer.data()));
  value = sanitizeUtf8Value(std::move(value));
  if (value.empty()) {
    return std::nullopt;
  }
  return value;
}

std::optional<std::vector<uint8_t>> readRecordValueBinary(
    libesedb_record_t* record, const int value_entry) {
  size_t binary_size = 0;
  const int size_result = libesedb_record_get_value_binary_data_size(
      record, value_entry, &binary_size, nullptr);
  if (size_result <= 0 || binary_size == 0) {
    return std::nullopt;
  }

  std::vector<uint8_t> data(binary_size);
  if (libesedb_record_get_value_binary_data(record, value_entry, data.data(),
                                            binary_size, nullptr) <= 0) {
    return std::nullopt;
  }
  return data;
}

std::optional<uint64_t> readRecordValueU64(libesedb_record_t* record,
                                           const int value_entry) {
  uint64_t value = 0;
  if (libesedb_record_get_value_64bit(record, value_entry, &value, nullptr) == 1) {
    return value;
  }

  uint32_t value32 = 0;
  if (libesedb_record_get_value_32bit(record, value_entry, &value32, nullptr) == 1) {
    return static_cast<uint64_t>(value32);
  }
  return std::nullopt;
}

std::optional<std::string> readRecordValueFiletimeString(
    libesedb_record_t* record, const int value_entry) {
  uint64_t filetime = 0;
  if (libesedb_record_get_value_filetime(record, value_entry, &filetime,
                                         nullptr) != 1) {
    return std::nullopt;
  }

  const std::string timestamp = formatReasonableFiletime(filetime);
  if (timestamp.empty()) {
    return std::nullopt;
  }
  return timestamp;
}

std::string getTableNameUtf8(libesedb_table_t* table) {
  size_t name_size = 0;
  if (libesedb_table_get_utf8_name_size(table, &name_size, nullptr) != 1 ||
      name_size == 0) {
    return {};
  }

  std::vector<uint8_t> buffer(name_size);
  if (libesedb_table_get_utf8_name(table, buffer.data(), name_size, nullptr) != 1) {
    return {};
  }

  std::string name(reinterpret_cast<char*>(buffer.data()));
  return sanitizeUtf8Value(std::move(name));
}

#endif

}  // namespace WindowsDiskAnalysis::ExecutionEvidenceDetail
