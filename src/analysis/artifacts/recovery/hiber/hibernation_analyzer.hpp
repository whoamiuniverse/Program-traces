/// @file hibernation_analyzer.hpp
/// @brief Анализатор `hiberfil.sys` (native libhibr + binary fallback)

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class HibernationAnalyzer
/// @brief Извлекает артефакты исполнения из `hiberfil.sys`.
///
/// @details Поддерживает:
///  - native режим через `libhibr` (экспериментальный);
///  - binary fallback через сигнатурно-строковый recovery-скан.
class HibernationAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Создаёт анализатор гибернационного файла.
  /// @param config_path Путь к `config.ini`.
  explicit HibernationAnalyzer(std::string config_path);

  /// @brief Собирает recovery evidence из `hiberfil.sys`.
  /// @param disk_root Корневой путь смонтированного Windows-тома.
  /// @return Набор восстановленных evidence.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Загружает параметры из секции `[Recovery]`.
  void loadConfiguration();

  std::string config_path_;  ///< Путь к INI-конфигурации.
  bool enabled_ = true;      ///< Включён ли анализ hiberfil.
  bool enable_native_hiber_parser_ =
      true;  ///< Использовать `libhibr` в native режиме.
  bool hiber_fallback_to_binary_ =
      true;  ///< Включать binary fallback при неуспехе native.
  std::size_t hiber_max_pages_ =
      16384;  ///< Максимум страниц для native-scan (4KB/page).
  std::size_t binary_scan_max_mb_ = 64;  ///< Лимит чтения для fallback.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Лимит извлечённых кандидатов.
  std::string hiber_path_ = "hiberfil.sys";  ///< Путь к hiberfil (от disk_root).
};

}  // namespace WindowsDiskAnalysis
