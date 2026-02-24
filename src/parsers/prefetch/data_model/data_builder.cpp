#include "data_builder.hpp"

#include <algorithm>

#include "infra/logging/logger.hpp"
#include "data.hpp"
#include "prefetch_versions.hpp"

namespace PrefetchAnalysis {

PrefetchDataBuilder& PrefetchDataBuilder::setExecutableName(
    const std::string& executable_name) noexcept {
  storage_.executable_name = executable_name;
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::setPrefetchHash(
    const uint32_t prefetch_hash) noexcept {
  storage_.prefetch_hash = prefetch_hash;
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::setRunCount(
    const uint32_t run_count) noexcept {
  storage_.run_count = run_count;
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::setFormatVersion(
    const uint8_t version) noexcept {
  storage_.format_version = version;
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::setLastRunTime(
    const uint64_t last_run_time) noexcept {
  storage_.last_run_time = last_run_time;
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::addRunTime(
    const uint64_t run_time) noexcept {
  storage_.run_times.push_back(run_time);
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::addVolume(VolumeInfo vol) noexcept {
  volume_cache_.push_back(std::move(vol));
  return *this;
}

PrefetchDataBuilder& PrefetchDataBuilder::addMetric(
    FileMetric metric) noexcept {
  metric_cache_.push_back(std::move(metric));
  return *this;
}

void PrefetchDataBuilder::validateCoreData() const {
  if (constexpr std::string_view forbidden = R"(\/:*?"<>|)";
      storage_.executable_name.empty() ||
      storage_.executable_name.find_first_of(forbidden) != std::string::npos) {
    throw InvalidExecutableNameException("имя файла не может быть пустым");
  }

  if (storage_.prefetch_hash == 0) {
    throw InvalidPrefetchHashException(storage_.prefetch_hash);
  }

  if (storage_.format_version ==
      static_cast<uint32_t>(PrefetchFormatVersion::UNKNOWN)) {
    throw InvalidVersionException(storage_.format_version);
  }
}

void PrefetchDataBuilder::validateRunTimes() const {
  auto logger = GlobalLogger::get();

  try {
    if (storage_.last_run_time == 0) {
      throw InvalidRunTimeException(storage_.last_run_time,
                                    "нулевое время последнего запуска");
    }
  } catch (const InvalidRunTimeException& e) {
    logger->debug(e.what());
  }

  constexpr uint64_t MAX_FILETIME = 0x01D9F3D6FDBD0000ULL;  // 01.01.2500
  try {
    if (storage_.last_run_time > MAX_FILETIME) {
      throw InvalidRunTimeException(storage_.last_run_time,
                                    "время последнего запуска превышает "
                                    "максимальное допустимое значение");
    }
  } catch (const InvalidRunTimeException& e) {
    logger->debug(e.what());
  }

  for (const auto& run_time : storage_.run_times) {
    try {
      if (run_time == 0) {
        throw InvalidRunTimeException(
            run_time, "обнаружено нулевое время запуска в массиве run_times");
      }
    } catch (const InvalidRunTimeException& e) {
      logger->debug(e.what());
    }

    try {
      if (run_time > MAX_FILETIME) {
        throw InvalidRunTimeException(run_time,
                                      "время запуска в массиве run_times "
                                      "превышает максимальное допустимое "
                                      "значение");
      }
    } catch (const InvalidRunTimeException& e) {
      logger->debug(e.what());
    }
  }
}

void PrefetchDataBuilder::validateVolumes() const {
  auto logger = GlobalLogger::get();

  for (const auto& volume : storage_.volumes) {
    const auto& device_path = volume.getDevicePath();

    logger->debug("Начало обработки устройства \"" + device_path + "\"");

    try {
      if (volume.getDevicePath().empty()) {
        throw VolumeValidationException(
            device_path, "путь к устройству не может быть пустым");
      }
    } catch (const VolumeValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (volume.getSerialNumber() == 0) {
        throw VolumeValidationException(
            device_path, "серийный номер тома не может быть нулевым");
      }
    } catch (const VolumeValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (volume.getVolumeSize() == 0) {
        throw VolumeValidationException(device_path,
                                        "размер тома не может быть нулевым");
      }
    } catch (const VolumeValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (volume.getCreationTime() == 0) {
        throw VolumeValidationException(
            device_path, "время создания тома не может быть нулевым");
      }
    } catch (const VolumeValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (volume.getVolumeType() ==
          static_cast<uint32_t>(VolumeType::UNKNOWN)) {
        throw VolumeValidationException(device_path,
                                        "неподдерживаемый тип тома");
      }
    } catch (const VolumeValidationException& e) {
      logger->debug(e.what());
    }

    logger->debug("Конец обработки устройства \"" + device_path + "\"");
  }
}

void PrefetchDataBuilder::validateMetric() const {
  auto logger = GlobalLogger::get();

  for (const auto& metric : storage_.metrics) {
    const auto& filename = metric.getFilename();

    logger->debug("Начало обработки файла\"" + filename + "\"");

    try {
      if (filename.empty()) {
        throw MetricValidationException(filename,
                                        "имя файла не может быть пустым");
      }
    } catch (const MetricValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (metric.getFileSize() == 0) {
        throw MetricValidationException(filename,
                                        "размер файла не может быть нулевым");
      }
    } catch (const MetricValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (metric.getLastAccessTime() == 0) {
        throw MetricValidationException(
            filename, "время последнего доступа не может быть нулевым");
      }
    } catch (const MetricValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (metric.getFileReference() == 0) {
        throw MetricValidationException(filename,
                                        "ссылка на MFT не может быть нулевой");
      }
    } catch (const MetricValidationException& e) {
      logger->debug(e.what());
    }

    try {
      if (metric.getAccessFlags() == 0) {
        throw MetricValidationException(filename,
                                        "флаги доступа не могут быть нулевыми");
      }
    } catch (const MetricValidationException& e) {
      logger->debug(e.what());
    }

    logger->debug("Конец обработки файла\"" + filename + "\"");
  }
}
std::unique_ptr<IPrefetchData> PrefetchDataBuilder::build() {
  validateCoreData();
  validateRunTimes();
  validateVolumes();
  validateMetric();

  storage_.volumes = std::move(volume_cache_);
  storage_.metrics = std::move(metric_cache_);

  return std::make_unique<PrefetchData>(std::move(storage_));
}

}
