/// @file registry_log_analyzer.hpp
/// @brief Recovery-анализатор транзакционных хвостов реестра (`LOG1/LOG2`).

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class RegistryLogAnalyzer
/// @brief Извлекает evidence из `*.LOG1/*.LOG2/*.regtrans-ms/*.blf`.
class RegistryLogAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Создает анализатор транзакционных логов реестра.
  /// @param config_path Путь к `config.ini`.
  explicit RegistryLogAnalyzer(std::string config_path);

  /// @brief Собирает recovery evidence из транзакционных файлов реестра.
  /// @param disk_root Корневой путь смонтированного Windows-тома.
  /// @return Набор восстановленных evidence.
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Загружает параметры из секции `[Recovery]`.
  void loadConfiguration();

  std::string config_path_;  ///< Путь к INI-конфигурации.
  bool enabled_ = true;      ///< Включен ли анализ registry transaction logs.
  std::size_t binary_scan_max_mb_ = 64;  ///< Byte-limit для binary scan.
  std::size_t max_candidates_per_source_ =
      2000;  ///< Лимит кандидатов на источник.
  std::string registry_config_path_ =
      "Windows/System32/config";  ///< Каталог hive/log-файлов.
};

}  // namespace WindowsDiskAnalysis
