/// @file usn_analyzer.hpp
/// @brief Анализатор источников восстановления USN/$LogFile

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis {

/// @class USNAnalyzer
/// @brief Извлекает кандидаты исполняемых файлов из USN/$LogFile
class USNAnalyzer final : public IRecoveryAnalyzer {
 public:
  /// @brief Конструктор анализатора USN/$LogFile
  /// @param config_path Путь к INI-конфигурации
  explicit USNAnalyzer(std::string config_path);

  /// @brief Собирает записи восстановления из USN/$LogFile
  /// @param disk_root Корень смонтированного Windows-раздела
  /// @return Набор восстановленных артефактов
  [[nodiscard]] std::vector<RecoveryEvidence> collect(
      const std::string& disk_root) const override;

 private:
  /// @brief Загружает параметры анализатора из секции `[Recovery]`
  void loadConfiguration();

  std::string config_path_;  ///< Путь к INI-конфигурации
  bool enabled_ = true;      ///< Включен ли анализ USN
  bool enable_logfile_ = true;  ///< Включен ли fallback-скан $LogFile
  bool enable_native_usn_parser_ = true;  ///< Использовать libfusn
  bool usn_fallback_to_binary_on_native_failure_ =
      true;  ///< Разрешить binary fallback при провале native USN
  std::size_t binary_scan_max_mb_ = 64;  ///< Лимит байтов для binary fallback
  std::size_t max_candidates_per_source_ =
      2000;  ///< Ограничение числа кандидатов на источник
  std::size_t native_usn_max_records_ =
      200000;  ///< Лимит записей USN для native-парсера
  std::string usn_journal_path_;  ///< Явный путь к экспортированному `$J`
};

}  // namespace WindowsDiskAnalysis
