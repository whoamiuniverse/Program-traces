#include "parser.hpp"

#include <algorithm>
#include <sstream>

#include "../../../utils/logging/logger.hpp"

namespace PrefetchAnalysis {

PrefetchParser::PrefetchParser() : scca_handle_(nullptr) {
  const auto logger = GlobalLogger::get();

  logger->debug("Инициализация парсера Prefetch-файлов");

  if (libscca_file_initialize(&scca_handle_, nullptr) != 1) {
    throw InitLibError("libscca");
  }

  logger->debug("Парсер успешно инициализирован");
}

PrefetchParser::~PrefetchParser() noexcept {
  if (scca_handle_) {
    libscca_file_free(&scca_handle_, nullptr);
  }
}

std::unique_ptr<IPrefetchData> PrefetchParser::parse(
    const std::string& path) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Начало обработки файла: \"{}\"", path);

  if (libscca_file_open(scca_handle_, path.c_str(), LIBSCCA_ACCESS_FLAG_READ,
                        nullptr) != 1) {
    throw FileOpenException(path);
  }

  PrefetchDataBuilder builder;

  parseBasicInfo(builder);

  try {
    parseRunTimes(builder);
  } catch (...) {
    logger->error("Ошибка при обработке файла: \"{}\"", path);
  }

  try {
    parseVolumes(builder);
  } catch (...) {
    logger->error("Ошибка при обработке файла: \"{}\"", path);
  }

  try {
    parseMetrics(builder);
  } catch (...) {
    logger->error("Ошибка при обработке файла: \"{}\"", path);
  }

  logger->debug("Файл успешно обработан");
  libscca_file_close(scca_handle_, nullptr);
  return builder.build();
}

void PrefetchParser::parseBasicInfo(PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение основной информации");

  char filename[256] = {};
  size_t name_length = 0;

  if (libscca_file_get_utf8_executable_filename_size(scca_handle_, &name_length,
                                                     nullptr) != 1 ||
      name_length == 0 || name_length > sizeof(filename) ||
      libscca_file_get_utf8_executable_filename(
          scca_handle_, reinterpret_cast<uint8_t*>(filename), name_length,
          nullptr) != 1) {
    throw DataReadException("ошибка чтения имени исполняемого файла");
  }
  builder.setExecutableName(filename);

  uint32_t prefetch_hash = 0;
  if (libscca_file_get_prefetch_hash(scca_handle_, &prefetch_hash, nullptr) !=
      1) {
    throw DataReadException("ошибка чтения хэша prefetch");
  }
  builder.setPrefetchHash(prefetch_hash);

  uint32_t run_count = 0;
  if (libscca_file_get_run_count(scca_handle_, &run_count, nullptr) != 1) {
    throw DataReadException("ошибка чтения счетчика запусков");
  }
  builder.setRunCount(run_count);

  uint32_t format_version = 0;
  if (libscca_file_get_format_version(scca_handle_, &format_version, nullptr) !=
      1) {
    throw DataReadException("ошибка чтения версии формата");
  }
  if (toVersionEnum(format_version) == PrefetchFormatVersion::UNKNOWN) {
    throw DataReadException("парсер не поддерживает версии " +
                            std::to_string(format_version) +
                            " Prefetch-файлов");
  }
  builder.setFormatVersion(format_version);
}

void PrefetchParser::parseRunTimes(PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение временных меток запусков");

  std::vector<uint64_t> valid_times;

  for (uint32_t i = 0;; ++i) {
    uint64_t filetime = 0;
    if (libscca_file_get_last_run_time(scca_handle_, i, &filetime, nullptr) !=
        1) {
      break;
    }

    if (filetime == 0) {
      logger->debug("Пропущена нулевая метка времени");
      continue;
    }

    try {
      time_t unix_time = convertFiletime(filetime);
      builder.addRunTime(unix_time);
      valid_times.push_back(filetime);
    } catch (const InvalidTimestampException& e) {
      logger->debug("Некорректная метка времени: \"{}\"", e.what());
    }
  }

  if (!valid_times.empty()) {
    const uint64_t last_run = *std::ranges::max_element(valid_times);
    builder.setLastRunTime(convertFiletime(last_run));
  }
}

void PrefetchParser::parseVolumes(PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение информации о томах");

  int32_t volume_count = 0;
  if (libscca_file_get_number_of_volumes(scca_handle_, &volume_count,
                                         nullptr) != 1) {
    throw DataReadException("Ошибка чтения количества томов");
  }

  for (int i = 0; i < volume_count; ++i) {
    libscca_volume_information_t* vol_info = nullptr;
    if (libscca_file_get_volume_information(scca_handle_, i, &vol_info,
                                            nullptr) != 1) {
      logger->debug("Ошибка чтения информации о томе \"{}\"", i);
      continue;
    }

    char device_path[256] = {};
    size_t path_size = 0;

    if (libscca_volume_information_get_utf8_device_path_size(
            vol_info, &path_size, nullptr) != 1 ||
        path_size == 0 || path_size > sizeof(device_path) ||
        libscca_volume_information_get_utf8_device_path(
            vol_info, reinterpret_cast<uint8_t*>(device_path), path_size,
            nullptr) != 1) {
      libscca_volume_information_free(&vol_info, nullptr);
      throw InvalidVolumeException("", "Ошибка чтения пути устройства");
    }

    std::string normalized_path(device_path);
    std::ranges::replace(normalized_path, '\\', '/');

    uint32_t serial = 0;
    uint64_t creation_time = 0;

    if (libscca_volume_information_get_serial_number(vol_info, &serial,
                                                     nullptr) != 1 ||
        libscca_volume_information_get_creation_time(vol_info, &creation_time,
                                                     nullptr) != 1) {
      libscca_volume_information_free(&vol_info, nullptr);
      throw InvalidVolumeException(normalized_path,
                                   "Ошибка чтения метаданных тома");
    }

    try {
      builder.addVolume(VolumeInfo(normalized_path, serial, creation_time));
    } catch (const std::exception& e) {
      logger->error("Ошибка обработки тома \"{}\": {}", normalized_path, e.what());
    }

    libscca_volume_information_free(&vol_info, nullptr);
  }
}

void PrefetchParser::parseMetrics(PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение файловых метрик");

  int metric_count = 0;
  if (libscca_file_get_number_of_file_metrics_entries(
          scca_handle_, &metric_count, nullptr) != 1) {
    throw DataReadException("Ошибка чтения количества метрик");
  }

  for (int i = 0; i < metric_count; ++i) {
    libscca_file_metrics_t* metric = nullptr;
    if (libscca_file_get_file_metrics_entry(scca_handle_, i, &metric,
                                            nullptr) != 1) {
      logger->debug("Ошибка чтения метрики \"{}\"", i);
      continue;
    }

    char filename[512] = {};
    size_t name_size = 0;

    if (libscca_file_metrics_get_utf8_filename_size(metric, &name_size,
                                                    nullptr) != 1 ||
        name_size == 0 || name_size > sizeof(filename) ||
        libscca_file_metrics_get_utf8_filename(
            metric, reinterpret_cast<uint8_t*>(filename), name_size, nullptr) !=
            1) {
      libscca_file_metrics_free(&metric, nullptr);
      throw InvalidFileMetricException("", "Ошибка чтения имени файла");
    }

    uint64_t file_ref = 0;
    if (libscca_file_metrics_get_file_reference(metric, &file_ref, nullptr) !=
        1) {
      libscca_file_metrics_free(&metric, nullptr);
      throw InvalidFileMetricException(filename, "Ошибка чтения MFT-ссылки");
    }

    try {
      std::string normalized_filename(filename);
      std::ranges::replace(normalized_filename, '\\', '/');
      builder.addMetric(FileMetric(normalized_filename, file_ref));
    } catch (const std::exception& e) {
      logger->error("Ошибка обработки метрики \"{}\": {}", filename, e.what());
    }

    libscca_file_metrics_free(&metric, nullptr);
  }
}

time_t PrefetchParser::convertFiletime(const uint64_t filetime) {
  if (filetime < FILETIME_EPOCH_DIFF || filetime > FILETIME_MAX_VALID) {
    std::ostringstream oss;
    oss << "Некорректное значение времени: 0x" << std::hex << filetime;
    throw InvalidTimestampException(filetime, oss.str());
  }
  return (filetime - FILETIME_EPOCH_DIFF) / 10000000ULL;
}

}
