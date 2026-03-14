/// @file windows_disk_analyzer.cpp
/// @brief Основной orchestration-пайплайн анализа артефактов Windows.

#include "windows_disk_analyzer.hpp"

#include <filesystem>
#include <memory>
#include <utility>

#include "analysis/artifacts/event_logs/eventlog_analyzer.hpp"
#include "analysis/artifacts/event_logs/security_context_analyzer.hpp"
#include "analysis/artifacts/recovery/fs_metadata/ntfs_metadata_analyzer.hpp"
#include "analysis/artifacts/recovery/hiber/hibernation_analyzer.hpp"
#include "analysis/artifacts/recovery/registry/registry_log_analyzer.hpp"
#include "analysis/artifacts/recovery/usn/usn_analyzer.hpp"
#include "analysis/artifacts/recovery/vss/vss_analyzer.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/event_log/evt/parser/parser.hpp"
#include "parsers/event_log/evtx/parser/parser.hpp"
#include "parsers/registry/parser/parser.hpp"
#include "windows_disk_analyzer_helpers.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace Orchestrator::Detail;

WindowsDiskAnalyzer::WindowsDiskAnalyzer(std::string disk_root,
                                         const std::string& config_path)
    : disk_root_(normalizeDiskRoot(std::move(disk_root))),
      config_path_(config_path) {
  const auto logger = GlobalLogger::get();

  if (disk_root_.empty()) {
    logger->info(
        "Корень анализа: auto (будет выполнен авто-поиск Windows-тома)");
  } else {
    logger->info("Корень анализа: \"{}\"", disk_root_);
  }
  logger->info("Загрузка конфигурации из файла: \"{}\"", config_path);
  detectOSVersion();
  initializeComponents();
}

void WindowsDiskAnalyzer::initializeComponents() {
  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.autorun);
    auto registry_parser = std::make_unique<RegistryAnalysis::RegistryParser>();
    autorun_analyzer_ = std::make_unique<AutorunAnalyzer>(
        std::move(registry_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.prefetch);
    auto prefetch_parser = std::make_unique<PrefetchAnalysis::PrefetchParser>();
    prefetch_analyzer_ = std::make_unique<PrefetchAnalyzer>(
        std::move(prefetch_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.eventlog);
    eventlog_collectors_.push_back(std::make_unique<EventLogAnalyzer>(
        std::make_unique<EventLogAnalysis::EvtParser>(),
        std::make_unique<EventLogAnalysis::EvtxParser>(),
        os_info_.ini_version, config_path_));

    eventlog_collectors_.push_back(std::make_unique<SecurityContextAnalyzer>(
        std::make_unique<EventLogAnalysis::EvtParser>(),
        std::make_unique<EventLogAnalysis::EvtxParser>(),
        os_info_.ini_version, config_path_));
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.amcache);
    auto amcache_registry_parser =
        std::make_unique<RegistryAnalysis::RegistryParser>();
    amcache_analyzer_ = std::make_unique<AmcacheAnalyzer>(
        std::move(amcache_registry_parser), os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.execution);
    execution_evidence_analyzer_ = std::make_unique<ExecutionEvidenceAnalyzer>(
        os_info_.ini_version, config_path_);
  }

  {
    ScopedDebugLevelOverride scoped_debug(debug_options_.recovery);
    recovery_analyzers_.push_back(
        {"USN", std::make_unique<USNAnalyzer>(config_path_)});
    recovery_analyzers_.push_back(
        {"VSS", std::make_unique<VSSAnalyzer>(config_path_)});
    recovery_analyzers_.push_back(
        {"Hiber", std::make_unique<HibernationAnalyzer>(config_path_)});
    recovery_analyzers_.push_back(
        {"NTFS", std::make_unique<NTFSMetadataAnalyzer>(config_path_)});
    recovery_analyzers_.push_back(
        {"Registry", std::make_unique<RegistryLogAnalyzer>(config_path_)});
  }
}

void WindowsDiskAnalyzer::ensureDirectoryExists(const std::string& path) {
  const fs::path dir_path = fs::path(path).parent_path();
  if (dir_path.empty()) {
    return;
  }

  std::error_code ec;
  if (fs::exists(dir_path, ec) && !ec) {
    return;
  }
  if (ec) {
    throw OutputDirectoryException(path, ec.message());
  }

  fs::create_directories(dir_path, ec);
  if (ec) {
    throw OutputDirectoryException(path, ec.message());
  }
}

void WindowsDiskAnalyzer::resetAnalysisState() {
  autorun_entries_.clear();
  process_data_.clear();
  network_connections_.clear();
  amcache_entries_.clear();
  global_tamper_flags_.clear();
  recovery_evidence_.clear();
}

void WindowsDiskAnalyzer::analyze(const std::string& output_path) {
  analyze(output_path, AnalyzeOutputOptions{});
}

void WindowsDiskAnalyzer::analyze(const std::string& output_path,
                                  const AnalyzeOutputOptions& options) {
  const auto logger = GlobalLogger::get();
  logger->info("Старт полного анализа артефактов");

  resetAnalysisState();
  runAutorunStage();
  runAmcacheStage();
  runPrefetchStage();
  runEventLogStage();
  runExecutionStage();
  runRecoveryStage();
  applyTamperRules();
  applyGlobalTamperFlags();
  exportCsv(output_path, options);

  logger->info("Анализ завершен: процессов={}, сетевых событий={}",
               process_data_.size(), network_connections_.size());
}

}  // namespace WindowsDiskAnalysis
