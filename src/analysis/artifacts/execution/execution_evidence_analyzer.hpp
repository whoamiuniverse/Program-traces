/// @file execution_evidence_analyzer.hpp
/// @brief Оркестратор расширенного этапа извлечения execution-артефактов.

#pragma once

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/execution/execution_evidence_config.hpp"
#include "analysis/artifacts/execution/iexecution_artifact_collector.hpp"

namespace WindowsDiskAnalysis {

/// @class ExecutionEvidenceAnalyzer
/// @brief Оркестратор, который загружает конфигурацию, инициализирует
/// коллекторы и запускает их.
///
/// @details Управляет четырьмя группами @c IExecutionArtifactCollector:
/// SOFTWARE-реестр, SYSTEM-реестр, файловая система и базы данных.
/// Группы могут выполняться параллельно.
class ExecutionEvidenceAnalyzer {
 public:
  /// @brief Создаёт оркестратор execution-источников.
  /// @param os_version Определённая версия Windows.
  /// @param ini_path   Путь к INI-конфигурации.
  ExecutionEvidenceAnalyzer(
      std::string os_version, std::string ini_path);

  /// @brief Обогащает агрегированную карту процессов execution-данными.
  /// @param disk_root    Корень анализируемого Windows-раздела.
  /// @param process_data Карта процессов (обновляется на месте).
  /// @details Оркестратор использует только источники из целевого набора
  /// из 11 артефактов запуска ПО.
  void collect(const std::string& disk_root,
               std::unordered_map<std::string, ProcessInfo>& process_data);

 private:
  /// @brief Загружает параметры из секции @c [ExecutionArtifacts].
  void loadConfiguration();

  /// @brief Регистрирует используемые execution-коллекторы.
  void initializeCollectors();

  /// @brief Псевдоним группы execution-коллекторов.
  using CollectorGroup = std::vector<std::unique_ptr<IExecutionArtifactCollector>>;

  std::string os_version_;  ///< Определённая версия Windows.
  std::string ini_path_;    ///< Путь к INI-конфигурации.
  ExecutionEvidenceConfig config_;  ///< Загруженная конфигурация анализа.
  bool enable_parallel_groups_ = false;  ///< Параллельный запуск групп коллекторов.
  bool enable_parallel_user_hive_analysis_ = false;  ///< Параллельный обход пользовательских hive.
  std::size_t worker_threads_ =
      std::max<std::size_t>(1, std::thread::hardware_concurrency());  ///< Число рабочих потоков.
  CollectorGroup software_collectors_;    ///< Коллекторы SOFTWARE-hive.
  CollectorGroup system_collectors_;      ///< Коллекторы SYSTEM-hive.
  CollectorGroup filesystem_collectors_;  ///< Коллекторы файловой системы.
  CollectorGroup database_collectors_;    ///< Коллекторы ESE/SQLite баз.
};

}  // namespace WindowsDiskAnalysis
