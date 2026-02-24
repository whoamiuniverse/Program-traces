/// @file file_metric.hpp
/// @brief Классы для работы с метаданными файла NTFS

#pragma once

#include <cstdint>
#include <filesystem>

#include "file_metric_access.hpp"

namespace PrefetchAnalysis {

/// @class FileMetric
/// @brief Контейнер метаданных файла NTFS
/// @details Инкапсулирует:
///    - Путь к файлу в формате NTFS
///    - Ссылку на MFT-запись
///    - Размер файла
///    - Флаги доступа
///    - Время последнего обращения
class FileMetric {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Основной конструктор
  /// @param[in] filename Абсолютный путь к файлу (NTFS формат)
  /// @param[in] mft_ref Ссылка на MFT-запись (64-битный идентификатор)
  /// @param[in] file_size Размер файла в байтах (0 по умолчанию)
  /// @param[in] access_flags Битовая маска флагов доступа (0 по умолчанию)
  /// @param[in] last_access_time Время последнего доступа в формате FILETIME
  /// @note Время задаётся в 100-нс интервалах от 01.01.1601 (UTC)
  FileMetric(std::string filename, uint64_t mft_ref, uint64_t file_size = 0,
             uint32_t access_flags = 0, uint64_t last_access_time = 0);

  /// @brief Деструктор по умолчанию
  ~FileMetric() = default;

  /// @}

  /// @name Геттеры
  /// @{

  /// @brief Возвращает абсолютный путь к файлу
  /// @return Константная ссылка на объект пути
  [[nodiscard]] const std::string& getFilename() const noexcept;

  /// @brief Возвращает идентификатор MFT-записи
  /// @return 64-битный беззнаковый идентификатор
  [[nodiscard]] uint64_t getFileReference() const noexcept;

  /// @brief Возвращает размер файла
  /// @return Размер в байтах
  [[nodiscard]] uint64_t getFileSize() const noexcept;

  /// @brief Возвращает флаги доступа
  /// @return Битовая маска флагов FileMetricAccess
  [[nodiscard]] uint32_t getAccessFlags() const noexcept;

  /// @brief Возвращает время последнего доступа
  /// @return 64-битное значение FILETIME в 100-нс интервалах от 01.01.1601
  /// (UTC)
  [[nodiscard]] uint64_t getLastAccessTime() const noexcept;

  /// @}

  /// @name Методы проверки флагов доступа
  /// @{

  /// @brief Общий метод проверки флагов доступа
  /// @tparam flag Проверяемый флаг из FileMetricAccess
  /// @return true если установлен указанный флаг
  template <FileMetricAccess flag>
  [[nodiscard]] bool checkAccessFlags() const noexcept;

  /// @brief Проверяет несколько флагов доступа одновременно (битовая маска)
  /// @param[in] types Комбинация флагов FileMetricAccess через битовое ИЛИ
  /// @return true если хотя бы один из указанных флагов присутствует
  [[nodiscard]] bool checkAccessFlag(uint32_t types) const noexcept;

  /// @}

 private:
  std::string filename_;       ///< Абсолютный путь к файлу
  uint64_t file_reference_;    ///< Идентификатор MFT-записи
  uint64_t file_size_;         ///< Размер файла в байтах
  uint32_t access_flags_;      ///< Битовая маска флагов доступа
  uint64_t last_access_time_;  ///< Время последнего обращения
};

}
