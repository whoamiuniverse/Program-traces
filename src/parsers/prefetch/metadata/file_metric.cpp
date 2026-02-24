#include "file_metric.hpp"

#include <utility>

namespace PrefetchAnalysis {

FileMetric::FileMetric(std::string filename, const uint64_t mft_ref,
                       const uint64_t file_size, const uint32_t access_flags,
                       const uint64_t last_access_time)
    : filename_(std::move(filename)),
      file_reference_(mft_ref),
      file_size_(file_size),
      access_flags_(access_flags),
      last_access_time_(last_access_time) {}

const std::string& FileMetric::getFilename() const noexcept {
  return filename_;
}

uint64_t FileMetric::getFileReference() const noexcept {
  return file_reference_;
}

uint64_t FileMetric::getFileSize() const noexcept { return file_size_; }

uint32_t FileMetric::getAccessFlags() const noexcept { return access_flags_; }

uint64_t FileMetric::getLastAccessTime() const noexcept {
  return last_access_time_;
}

template <FileMetricAccess flag>
[[nodiscard]] bool FileMetric::checkAccessFlags() const noexcept {
  return (access_flags_ & static_cast<uint32_t>(flag)) != 0;
}

[[nodiscard]] bool FileMetric::checkAccessFlag(
    const uint32_t types) const noexcept {
  return (access_flags_ & types) != 0;
}

}
