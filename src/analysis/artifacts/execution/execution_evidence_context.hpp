/// @file execution_evidence_context.hpp
/// @brief Контекст, передаваемый каждому коллектору артефактов исполнения.
#pragma once

#include <cstddef>
#include <string>

#include "analysis/artifacts/execution/execution_evidence_config.hpp"

namespace WindowsDiskAnalysis {

/// @struct ExecutionEvidenceContext
/// @brief Неизменяемый срез входных данных, передаваемый каждому коллектору.
struct ExecutionEvidenceContext {
  std::string disk_root;  ///< Корень анализируемого Windows-раздела.
  std::string software_hive_path;  ///< Разрешенный путь к SOFTWARE hive.
  std::string system_hive_path;  ///< Разрешенный путь к SYSTEM hive.
  bool enable_parallel_user_hives =
      false;  ///< Разрешен ли параллельный обход пользовательских hive.
  std::size_t worker_threads = 1;  ///< Верхняя граница числа рабочих потоков.
  const ExecutionEvidenceConfig& config;  ///< Ссылка на загруженную конфигурацию анализа.
};

}  // namespace WindowsDiskAnalysis
