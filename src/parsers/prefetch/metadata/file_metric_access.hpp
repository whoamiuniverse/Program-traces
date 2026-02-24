/// @file file_metric_access.hpp
/// @brief Флаги доступа к файлу

#pragma once

#include <cstdint>

namespace PrefetchAnalysis {

/// @enum FileMetricAccess
/// @brief Флаги доступа к файлу (соответствуют Windows API)
/// @see
/// https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
enum class FileMetricAccess : uint32_t {
  READ = 0x0001,         ///< FILE_READ_DATA (чтение данных из файла)
  WRITE = 0x0002,        ///< FILE_WRITE_DATA (запись данных в файл)
  APPEND = 0x0004,       ///< FILE_APPEND_DATA (дописывание в конец файла)
  EXECUTE = 0x0020,      ///< FILE_EXECUTE (исполнение файла)
  DELETE = 0x00010000L,  ///< DELETE (право удаления)
  ATTRIB = 0x0100        ///< FILE_WRITE_ATTRIBUTES (изменение атрибутов)
};

}
