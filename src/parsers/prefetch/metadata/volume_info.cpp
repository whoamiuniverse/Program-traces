#include "volume_info.hpp"

#include <algorithm>
#include <sstream>

namespace PrefetchAnalysis {

VolumeInfo::VolumeInfo(std::string device_path, const uint32_t serial_number,
                       const uint64_t creation_time, const uint64_t volume_size,
                       const uint32_t volume_type)
    : device_path_(std::move(device_path)),
      serial_number_(serial_number),
      creation_time_(creation_time),
      volume_size_(volume_size),
      volume_type_(volume_type) {}

const std::string& VolumeInfo::getDevicePath() const noexcept {
  return device_path_;
}

uint32_t VolumeInfo::getSerialNumber() const noexcept { return serial_number_; }

uint64_t VolumeInfo::getCreationTime() const noexcept { return creation_time_; }

uint64_t VolumeInfo::getVolumeSize() const noexcept { return volume_size_; }

uint32_t VolumeInfo::getVolumeType() const noexcept { return volume_type_; }

template <VolumeType type>
bool VolumeInfo::checkVolumeType() const noexcept {
  return (volume_type_ & static_cast<uint32_t>(type)) != 0;
}

bool VolumeInfo::checkVolumeTypes(const uint32_t types) const noexcept {
  return (volume_type_ & types) != 0;
}

}
