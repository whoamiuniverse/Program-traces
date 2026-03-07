/// @file execution_evidence_analyzer.hpp
/// @brief Оркестратор дополнительных источников исполнения процессов.

#pragma once

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/execution/execution_evidence_config.hpp"
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"
#include "analysis/artifacts/execution/itamper_signal_detector.hpp"

namespace WindowsDiskAnalysis {

/// @class ExecutionEvidenceAnalyzer
/// @brief Оркестратор: загружает конфигурацию, инициализирует коллекторы и запускает их.
class ExecutionEvidenceAnalyzer {
 public:
  /// @brief Создает оркестратор анализа источников исполнения.
  /// @param os_version Обнаруженная версия Windows.
  /// @param ini_path Путь к конфигурационному INI-файлу.
  ExecutionEvidenceAnalyzer(
      std::string os_version, std::string ini_path);

  /// @brief Обогащает карту процессов источниками исполнения и таймлайном.
  /// @param disk_root Корень Windows-раздела.
  /// @param process_data Агрегированные данные процессов (изменяются).
  /// @param global_tamper_flags Глобальные tamper-флаги (дополняются).
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data,
               std::vector<std::string>& global_tamper_flags);

 private:
  /// @brief Загружает настройки секции `[ExecutionArtifacts]`.
  void loadConfiguration();

  /// @brief Регистрирует доступные коллекторы и детекторы tamper-сигналов.
  void initializeCollectors();

  std::string os_version_;
  std::string ini_path_;
  ExecutionEvidenceConfig config_;
  bool enable_parallel_user_hive_analysis_ = false;
  std::size_t worker_threads_ =
      std::max<std::size_t>(1, std::thread::hardware_concurrency());
  std::vector<std::unique_ptr<IExecutionArtifactCollector>> collectors_;
  std::vector<std::unique_ptr<ITamperSignalDetector>> tamper_detectors_;
};

}  // namespace WindowsDiskAnalysis
