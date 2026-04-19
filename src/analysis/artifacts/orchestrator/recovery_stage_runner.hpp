/// @file recovery_stage_runner.hpp
/// @brief Testable helper functions for recovery-stage orchestration.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/recovery/irecovery_analyzer.hpp"

namespace WindowsDiskAnalysis::Orchestrator::RecoveryStage {

/// @brief Non-owning reference to a recovery analyzer and its log label.
struct RecoveryAnalyzerRef {
  std::string_view label;
  const IRecoveryAnalyzer* analyzer = nullptr;
};

/// @brief Per-analyzer execution slot with outputs and runtime metrics.
struct RecoveryStageSlot {
  std::string_view label;
  std::vector<RecoveryEvidence> evidence;
  std::size_t error_count = 0;
  std::uint64_t duration_ms = 0;
};

/// @brief Ensures that all mandatory recovery modules are present.
/// @throws DiskAnalyzerException when any mandatory module is missing.
void ensureMandatoryRecoveryAnalyzersRegistered(
    const std::vector<RecoveryAnalyzerRef>& analyzers);

/// @brief Creates stage slots aligned with analyzer order.
[[nodiscard]] std::vector<RecoveryStageSlot> createRecoveryStageSlots(
    const std::vector<RecoveryAnalyzerRef>& analyzers);

/// @brief Runs all recovery collectors concurrently.
void runRecoveryStageCollectorsInParallel(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer);

/// @brief Runs all recovery collectors sequentially.
void runRecoveryStageCollectorsSequentially(
    const std::vector<RecoveryAnalyzerRef>& analyzers,
    const std::string& disk_root,
    std::vector<RecoveryStageSlot>& per_analyzer);

/// @brief Canonicalizes, sorts, merges, and summarizes per-analyzer outputs.
[[nodiscard]] std::string mergeRecoveryEvidenceResults(
    std::vector<RecoveryStageSlot>& per_analyzer,
    std::unordered_map<std::string, ProcessInfo>& process_data,
    std::vector<RecoveryEvidence>& recovery_evidence);

}  // namespace WindowsDiskAnalysis::Orchestrator::RecoveryStage
