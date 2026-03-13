/// @file ntfs_metadata_analyzer.hpp
/// @brief Анализатор NTFS-метаданных (`$MFT`/`$Bitmap`) для recovery.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class NTFSMetadataAnalyzer
/// @brief Извлекает признаки удаленных исполняемых файлов из `$MFT/$Bitmap`.
///
/// @details Поддерживает fallback-парсинг:
///  - `$MFT`: поиск FILE-record + extraction кандидатов запуска;
///  - `$Bitmap`: сигнатурно-строковый scan.
/// Native `libfsntfs` подключается опционально.
class NTFSMetadataAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Создает анализатор NTFS-метаданных.
  /// @param config_path Путь к `config.ini`.
  explicit NTFSMetadataAnalyzer(std::string config_path);

  /// @brief Собирает recovery evidence из NTFS-метаданных.
  /// @param disk_root Корневой путь смонтированного Windows-тома.
  /// @return Набор восстановленных evidence.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Загружает параметры из секции `[Recovery]`.
  void loadConfiguration();

  std::string config_path_;  ///< Путь к INI-конфигурации.
  bool enabled_ = true;      ///< Включен ли анализ NTFS-метаданных.
  bool enable_native_fsntfs_parser_ =
      true;  ///< Использовать native parser (optional).
  bool fsntfs_fallback_to_binary_on_native_failure_ =
      true;  ///< Разрешить fallback при неуспехе native.
  std::size_t binary_scan_max_mb_ = 64;  ///< Byte-limit для binary scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Лимит кандидатов на источник.
  std::size_t mft_record_size_ = 1024;  ///< Размер MFT record для fallback.
  std::size_t mft_max_records_ = 200000;  ///< Лимит анализируемых MFT records.
  std::string mft_path_ = "$MFT";         ///< Путь к `$MFT`.
  std::string bitmap_path_ = "$Bitmap";   ///< Путь к `$Bitmap`.
  bool enable_si_fn_divergence_check_ = true;  ///< Проверка SI/FN divergence.
  std::size_t timestamp_divergence_threshold_sec_ = 2;
};

}  // namespace WindowsDiskAnalysis
