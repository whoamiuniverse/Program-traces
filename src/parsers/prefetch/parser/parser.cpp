#include "parser.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <sstream>
#include <utility>
#include <vector>

#include "infra/logging/logger.hpp"

namespace PrefetchAnalysis {

namespace {

template <typename F>
class ScopeExit {
 public:
  explicit ScopeExit(F&& fn) : fn_(std::forward<F>(fn)) {}
  ScopeExit(const ScopeExit&) = delete;
  ScopeExit& operator=(const ScopeExit&) = delete;
  ScopeExit(ScopeExit&& other) noexcept
      : fn_(std::move(other.fn_)), active_(other.active_) {
    other.active_ = false;
  }
  ~ScopeExit() {
    if (active_) fn_();
  }

 private:
  F fn_;
  bool active_ = true;
};

template <typename F>
ScopeExit<F> makeScopeExit(F&& fn) {
  return ScopeExit<F>(std::forward<F>(fn));
}

}  // namespace

PrefetchParser::PrefetchParser() {
  const auto logger = GlobalLogger::get();

  const char* version = libscca_get_version();
  logger->debug("Инициализация парсера Prefetch-файлов (libscca: {})",
                version == nullptr ? "unknown" : version);
}

PrefetchParser::~PrefetchParser() noexcept = default;

std::unique_ptr<IPrefetchData> PrefetchParser::parse(
    const std::string& path) const {
  const auto logger = GlobalLogger::get();
  libscca_file_t* scca_handle = nullptr;
  libscca_error_t* libscca_error = nullptr;

  if (libscca_file_initialize(&scca_handle, &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw InitLibError("libscca: " + details);
  }

  auto handle_guard = makeScopeExit([&]() {
    if (scca_handle == nullptr) return;

    libscca_error_t* free_error = nullptr;
    if (libscca_file_free(&scca_handle, &free_error) != 1) {
      logger->warn("Не удалось освободить handle Prefetch-файла: {}",
                   toLibsccaErrorMessage(free_error));
    }
    libscca_error_free(&free_error);
  });

  bool is_open = false;
  auto close_guard = makeScopeExit([&]() {
    if (!is_open || scca_handle == nullptr) return;

    libscca_error_t* close_error = nullptr;
    if (libscca_file_close(scca_handle, &close_error) != 0) {
      logger->warn("Не удалось корректно закрыть Prefetch-файл \"{}\": {}", path,
                   toLibsccaErrorMessage(close_error));
    }
    libscca_error_free(&close_error);
  });

  logger->debug("Начало обработки файла: \"{}\"", path);

  libscca_error = nullptr;
  if (libscca_file_open(scca_handle, path.c_str(), LIBSCCA_ACCESS_FLAG_READ,
                        &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw FileOpenException(path, details);
  }
  is_open = true;

  PrefetchDataBuilder builder;

  parseBasicInfo(scca_handle, builder);

  try {
    parseRunTimes(scca_handle, builder);
  } catch (const std::exception& e) {
    logger->warn("Ошибка чтения времени запусков в файле \"{}\": {}", path,
                 e.what());
  }

  try {
    parseVolumes(scca_handle, builder);
  } catch (const std::exception& e) {
    logger->warn("Ошибка чтения томов в файле \"{}\": {}", path, e.what());
  }

  try {
    parseMetrics(scca_handle, builder);
  } catch (const std::exception& e) {
    logger->warn("Ошибка чтения метрик в файле \"{}\": {}", path, e.what());
  }

  logger->debug("Файл успешно обработан");
  return builder.build();
}

void PrefetchParser::parseBasicInfo(libscca_file_t* scca_handle,
                                    PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение основной информации");

  size_t name_length = 0;
  libscca_error_t* libscca_error = nullptr;

  if (libscca_file_get_utf8_executable_filename_size(scca_handle, &name_length,
                                                     &libscca_error) != 1 ||
      name_length <= 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw DataReadException("ошибка чтения имени исполняемого файла: " +
                            details);
  }
  libscca_error_free(&libscca_error);

  std::vector<uint8_t> executable_name_buffer(name_length, 0);
  libscca_error = nullptr;
  if (libscca_file_get_utf8_executable_filename(
          scca_handle, executable_name_buffer.data(),
          executable_name_buffer.size(), &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw DataReadException("ошибка чтения имени исполняемого файла: " +
                            details);
  }
  libscca_error_free(&libscca_error);

  const std::string executable_name(
      reinterpret_cast<const char*>(executable_name_buffer.data()));
  if (executable_name.empty()) {
    throw DataReadException("имя исполняемого файла пустое");
  }
  builder.setExecutableName(executable_name);

  uint32_t prefetch_hash = 0;
  libscca_error = nullptr;
  if (libscca_file_get_prefetch_hash(scca_handle, &prefetch_hash,
                                     &libscca_error) != 1) {
    logger->debug("Хэш prefetch недоступен: {}",
                  toLibsccaErrorMessage(libscca_error));
  }
  libscca_error_free(&libscca_error);
  builder.setPrefetchHash(prefetch_hash);

  uint32_t run_count = 0;
  libscca_error = nullptr;
  if (libscca_file_get_run_count(scca_handle, &run_count, &libscca_error) != 1) {
    logger->debug("Счётчик запусков недоступен: {}",
                  toLibsccaErrorMessage(libscca_error));
  }
  libscca_error_free(&libscca_error);
  builder.setRunCount(run_count);

  uint32_t format_version = 0;
  libscca_error = nullptr;
  if (libscca_file_get_format_version(scca_handle, &format_version,
                                      &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw DataReadException("ошибка чтения версии формата: " + details);
  }
  libscca_error_free(&libscca_error);

  if (format_version > std::numeric_limits<uint8_t>::max()) {
    throw DataReadException("версия формата Prefetch вне диапазона uint8: " +
                            std::to_string(format_version));
  }

  if (toVersionEnum(format_version) == PrefetchFormatVersion::UNKNOWN) {
    logger->warn(
        "Обнаружена неизвестная версия Prefetch формата: {}. "
        "Обработка будет продолжена в режиме совместимости",
        format_version);
  }
  builder.setFormatVersion(static_cast<uint8_t>(format_version));
}

void PrefetchParser::parseRunTimes(libscca_file_t* scca_handle,
                                   PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение временных меток запусков");

  constexpr int kMaxRunTimes = 8;
  std::vector<uint64_t> valid_unix_times;
  valid_unix_times.reserve(kMaxRunTimes);

  for (int i = 0; i < kMaxRunTimes; ++i) {
    uint64_t filetime = 0;
    libscca_error_t* libscca_error = nullptr;
    if (libscca_file_get_last_run_time(scca_handle, i, &filetime,
                                       &libscca_error) != 1) {
      libscca_error_free(&libscca_error);
      break;
    }
    libscca_error_free(&libscca_error);

    if (filetime == 0) {
      continue;
    }

    try {
      const uint64_t unix_time = convertFiletime(filetime);
      builder.addRunTime(unix_time);
      valid_unix_times.push_back(unix_time);
    } catch (const InvalidTimestampException& e) {
      logger->debug("Некорректная метка времени: \"{}\"", e.what());
    }
  }

  if (!valid_unix_times.empty()) {
    builder.setLastRunTime(*std::ranges::max_element(valid_unix_times));
  }
}

void PrefetchParser::parseVolumes(libscca_file_t* scca_handle,
                                  PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение информации о томах");

  int32_t volume_count = 0;
  libscca_error_t* libscca_error = nullptr;
  if (libscca_file_get_number_of_volumes(scca_handle, &volume_count,
                                         &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw DataReadException("ошибка чтения количества томов: " + details);
  }
  libscca_error_free(&libscca_error);

  for (int i = 0; i < volume_count; ++i) {
    libscca_volume_information_t* vol_info = nullptr;
    libscca_error = nullptr;
    if (libscca_file_get_volume_information(scca_handle, i, &vol_info,
                                            &libscca_error) != 1) {
      logger->debug("Ошибка чтения информации о томе \"{}\": {}", i,
                    toLibsccaErrorMessage(libscca_error));
      libscca_error_free(&libscca_error);
      continue;
    }
    libscca_error_free(&libscca_error);

    auto volume_guard = makeScopeExit([&]() {
      if (vol_info == nullptr) return;
      libscca_error_t* free_error = nullptr;
      if (libscca_volume_information_free(&vol_info, &free_error) != 1) {
        logger->debug("Не удалось освободить volume_information: {}",
                      toLibsccaErrorMessage(free_error));
      }
      libscca_error_free(&free_error);
    });

    size_t path_size = 0;
    std::string normalized_path;
    libscca_error = nullptr;

    if (libscca_volume_information_get_utf8_device_path_size(
            vol_info, &path_size, &libscca_error) == 1 &&
        path_size > 1) {
      libscca_error_free(&libscca_error);
      std::vector<uint8_t> device_path_buffer(path_size, 0);
      libscca_error = nullptr;
      if (libscca_volume_information_get_utf8_device_path(
              vol_info, device_path_buffer.data(), device_path_buffer.size(),
              &libscca_error) == 1) {
        normalized_path.assign(
            reinterpret_cast<const char*>(device_path_buffer.data()));
        std::ranges::replace(normalized_path, '\\', '/');
      } else {
        logger->debug("Ошибка чтения пути устройства тома {}: {}", i,
                      toLibsccaErrorMessage(libscca_error));
      }
      libscca_error_free(&libscca_error);
    } else {
      logger->debug("Путь устройства для тома {} недоступен: {}", i,
                    toLibsccaErrorMessage(libscca_error));
      libscca_error_free(&libscca_error);
    }

    uint32_t serial = 0;
    uint64_t creation_time = 0;
    libscca_error = nullptr;
    if (libscca_volume_information_get_serial_number(vol_info, &serial,
                                                     &libscca_error) != 1) {
      logger->debug("Серийный номер тома {} недоступен: {}", i,
                    toLibsccaErrorMessage(libscca_error));
    }
    libscca_error_free(&libscca_error);

    libscca_error = nullptr;
    if (libscca_volume_information_get_creation_time(vol_info, &creation_time,
                                                     &libscca_error) != 1) {
      logger->debug("Время создания тома {} недоступно: {}", i,
                    toLibsccaErrorMessage(libscca_error));
    }
    libscca_error_free(&libscca_error);

    try {
      builder.addVolume(VolumeInfo(normalized_path, serial, creation_time));
    } catch (const std::exception& e) {
      logger->debug("Ошибка обработки тома \"{}\": {}", normalized_path,
                    e.what());
    }
  }
}

void PrefetchParser::parseMetrics(libscca_file_t* scca_handle,
                                  PrefetchDataBuilder& builder) const {
  const auto logger = GlobalLogger::get();

  logger->debug("Извлечение файловых метрик");

  int metric_count = 0;
  libscca_error_t* libscca_error = nullptr;
  if (libscca_file_get_number_of_file_metrics_entries(
          scca_handle, &metric_count, &libscca_error) != 1) {
    const std::string details = toLibsccaErrorMessage(libscca_error);
    libscca_error_free(&libscca_error);
    throw DataReadException("ошибка чтения количества метрик: " + details);
  }
  libscca_error_free(&libscca_error);

  for (int i = 0; i < metric_count; ++i) {
    libscca_file_metrics_t* metric = nullptr;
    libscca_error = nullptr;
    if (libscca_file_get_file_metrics_entry(scca_handle, i, &metric,
                                            &libscca_error) != 1) {
      logger->debug("Ошибка чтения метрики \"{}\": {}", i,
                    toLibsccaErrorMessage(libscca_error));
      libscca_error_free(&libscca_error);
      continue;
    }
    libscca_error_free(&libscca_error);

    auto metric_guard = makeScopeExit([&]() {
      if (metric == nullptr) return;
      libscca_error_t* free_error = nullptr;
      if (libscca_file_metrics_free(&metric, &free_error) != 1) {
        logger->debug("Не удалось освободить file_metrics: {}",
                      toLibsccaErrorMessage(free_error));
      }
      libscca_error_free(&free_error);
    });

    size_t name_size = 0;
    libscca_error = nullptr;
    if (libscca_file_metrics_get_utf8_filename_size(metric, &name_size,
                                                    &libscca_error) != 1 ||
        name_size <= 1) {
      logger->debug("Имя файла для метрики {} недоступно: {}", i,
                    toLibsccaErrorMessage(libscca_error));
      libscca_error_free(&libscca_error);
      continue;
    }
    libscca_error_free(&libscca_error);

    std::vector<uint8_t> filename_buffer(name_size, 0);
    libscca_error = nullptr;
    if (libscca_file_metrics_get_utf8_filename(metric, filename_buffer.data(),
                                               filename_buffer.size(),
                                               &libscca_error) != 1) {
      logger->debug("Ошибка чтения имени файла для метрики {}: {}", i,
                    toLibsccaErrorMessage(libscca_error));
      libscca_error_free(&libscca_error);
      continue;
    }
    libscca_error_free(&libscca_error);

    std::string normalized_filename(
        reinterpret_cast<const char*>(filename_buffer.data()));
    std::ranges::replace(normalized_filename, '\\', '/');
    if (normalized_filename.empty()) continue;

    uint64_t file_ref = 0;
    libscca_error = nullptr;
    const int file_ref_result =
        libscca_file_metrics_get_file_reference(metric, &file_ref,
                                                &libscca_error);
    if (file_ref_result == -1) {
      logger->debug("Ошибка чтения MFT-ссылки для \"{}\": {}",
                    normalized_filename, toLibsccaErrorMessage(libscca_error));
    }
    libscca_error_free(&libscca_error);

    try {
      builder.addMetric(FileMetric(normalized_filename, file_ref));
    } catch (const std::exception& e) {
      logger->debug("Ошибка обработки метрики \"{}\": {}", normalized_filename,
                    e.what());
    }
  }
}

uint64_t PrefetchParser::convertFiletime(const uint64_t filetime) {
  if (filetime < FILETIME_EPOCH_DIFF || filetime > FILETIME_MAX_VALID) {
    std::ostringstream oss;
    oss << "Некорректное значение времени: 0x" << std::hex << filetime;
    throw InvalidTimestampException(filetime, oss.str());
  }
  return (filetime - FILETIME_EPOCH_DIFF) / 10000000ULL;
}

std::string PrefetchParser::toLibsccaErrorMessage(libscca_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libscca";

  std::array<char, 2048> buffer{};
  if (libscca_error_sprint(error, buffer.data(), buffer.size()) > 0) {
    return std::string(buffer.data());
  }
  return "не удалось получить текст ошибки libscca";
}

}
