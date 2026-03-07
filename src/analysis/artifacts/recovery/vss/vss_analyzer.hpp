/// @file vss_analyzer.hpp
/// @brief Анализатор источников восстановления VSS/Pagefile/Memory

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class VSSAnalyzer
/// @brief Извлекает кандидаты исполняемых файлов из VSS и volatile-источников
class VSSAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Конструктор анализатора VSS/Pagefile/Memory
  /// @param config_path Путь к INI-конфигурации
  explicit VSSAnalyzer(std::string config_path);

  /// @brief Собирает записи восстановления из VSS и volatile-источников
  /// @param disk_root Корень смонтированного Windows-раздела
  /// @return Набор восстановленных артефактов
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Загружает параметры анализатора из секции `[Recovery]`
  void loadConfiguration();

  std::string config_path_;  ///< Путь к INI-конфигурации
  bool enabled_ = true;      ///< Включен ли анализ VSS
  bool enable_pagefile_ = true;     ///< Включен ли анализ `pagefile/swapfile`
  bool enable_memory_ = true;       ///< Включен ли анализ `hiberfil/MEMORY.DMP`
  bool enable_unallocated_ = true;  ///< Включен ли анализ внешнего unallocated image
  bool enable_native_vss_parser_ = true;  ///< Использовать libvshadow
  bool vss_fallback_to_binary_on_native_failure_ =
      true;  ///< Разрешить binary fallback при провале native VSS
  std::size_t binary_scan_max_mb_ = 64;  ///< Лимит байтов для binary fallback
  std::size_t max_candidates_per_source_ =
      2000;  ///< Ограничение числа кандидатов на источник
  std::size_t vss_native_max_stores_ =
      32;  ///< Лимит snapshot stores для native VSS
  std::string vss_volume_path_;  ///< Явный raw/device источник для native VSS
  std::string unallocated_image_path_;  ///< Путь к файлу с нераспределенным пространством
  bool enable_snapshot_artifact_replay_ =
      true;  ///< Повторный scan ключевых артефактов по VSS snapshot roots.
  std::size_t vss_snapshot_replay_max_files_ =
      200;  ///< Лимит файлов для VSS snapshot replay.
};

}  // namespace WindowsDiskAnalysis
