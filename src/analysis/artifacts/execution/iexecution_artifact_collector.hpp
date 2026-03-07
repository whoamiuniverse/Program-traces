/// @file iexecution_artifact_collector.hpp
/// @brief Интерфейс атомарного коллектора артефактов исполнения.
#pragma once

#include <string>
#include <unordered_map>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/execution/execution_evidence_context.hpp"

namespace WindowsDiskAnalysis {

/// @class IExecutionArtifactCollector
/// @brief Интерфейс атомарного сборщика одного типа execution-артефакта.
/// @details Каждая реализация:
///   - Проверяет свой флаг enable_X в ctx.config в начале collect() и возвращается если disabled.
///   - Для доступа к реестру создаёт локальный RegistryAnalysis::RegistryParser local_parser.
///   - Не хранит изменяемого состояния и может безопасно переиспользоваться.
class IExecutionArtifactCollector {
 public:
  /// @brief Виртуальный деструктор базового интерфейса.
  virtual ~IExecutionArtifactCollector() = default;

  /// @brief Собирает артефакты исполнения и обогащает process_data.
  /// @param ctx Контекст анализа: пути, конфиг и ограничения параллелизма.
  /// @param process_data Карта процессов для обогащения.
  virtual void collect(const ExecutionEvidenceContext& ctx,
                       std::unordered_map<std::string, ProcessInfo>& process_data) = 0;
};

}  // namespace WindowsDiskAnalysis
