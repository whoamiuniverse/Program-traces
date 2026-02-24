#include "data.hpp"

#include <algorithm>
#include <filesystem>

namespace PrefetchAnalysis {

namespace fs = std::filesystem;

PrefetchData::PrefetchData(PrefetchDataStorage&& storage)
    : storage_(std::move(storage)) {}

std::string PrefetchData::getExecutableName() const noexcept {
  return storage_.executable_name;
}

uint32_t PrefetchData::getPrefetchHash() const noexcept {
  return storage_.prefetch_hash;
}

uint32_t PrefetchData::getRunCount() const noexcept {
  return storage_.run_count;
}

const std::vector<uint64_t>& PrefetchData::getRunTimes() const noexcept {
  return storage_.run_times;
}

uint64_t PrefetchData::getLastRunTime() const noexcept {
  return storage_.last_run_time;
}

const std::vector<VolumeInfo>& PrefetchData::getVolumes() const noexcept {
  return storage_.volumes;
}

VolumeInfo PrefetchData::getMainVolume() const {
  return storage_.volumes.front();
}

const std::vector<FileMetric>& PrefetchData::getMetrics() const noexcept {
  return storage_.metrics;
}

std::vector<FileMetric> PrefetchData::getDllMetrics() const {
  std::vector<FileMetric> result;
  std::ranges::copy_if(
      storage_.metrics, std::back_inserter(result),
      [](const FileMetric& metric) {
        const auto ext = fs::path(metric.getFilename()).extension().string();
        return ext == ".dll" || ext == ".DLL";
      });
  return result;
}

uint8_t PrefetchData::getFormatVersion() const noexcept {
  return storage_.format_version;
}

[[nodiscard]] auto PrefetchData::isVersionSupported(
    const PrefetchFormatVersion version) const noexcept -> bool {
  return version != PrefetchFormatVersion::UNKNOWN;
}

}
