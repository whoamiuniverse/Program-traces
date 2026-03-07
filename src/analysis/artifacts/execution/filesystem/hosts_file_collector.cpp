/// @file hosts_file_collector.cpp
/// @brief Реализация HostsFileCollector.
#include "hosts_file_collector.hpp"

#include <filesystem>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::toLowerAscii;

void HostsFileCollector::collect(const ExecutionEvidenceContext& ctx,
                                 std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_hosts_file) return;
  const auto logger = GlobalLogger::get();
  if (ctx.config.hosts_file_path.empty()) {
    logger->info("Hosts: добавлено 0 запись(ей)");
    return;
  }

  const fs::path hosts_path = fs::path(ctx.disk_root) / ctx.config.hosts_file_path;
  const auto resolved_hosts_path = findPathCaseInsensitive(hosts_path);
  if (!resolved_hosts_path.has_value()) {
    logger->info("Hosts: добавлено 0 запись(ей)");
    return;
  }

  std::ifstream hosts_stream(*resolved_hosts_path);
  if (!hosts_stream.is_open()) {
    logger->warn("Hosts: не удалось открыть \"{}\"",
                 resolved_hosts_path->string());
    return;
  }

  std::error_code ec;
  const std::string hosts_timestamp =
      fileTimeToUtcString(fs::last_write_time(*resolved_hosts_path, ec));

  const std::string network_context_key = networkContextProcessKey();
  std::unordered_set<std::string> seen;
  std::size_t collected = 0;

  std::string line;
  while (std::getline(hosts_stream, line) &&
         collected < ctx.config.max_candidates_per_source) {
    std::string normalized_line = trim_copy(line);
    if (normalized_line.empty()) continue;

    const std::size_t comment_pos = normalized_line.find('#');
    if (comment_pos != std::string::npos) {
      normalized_line = normalized_line.substr(0, comment_pos);
      trim(normalized_line);
      if (normalized_line.empty()) continue;
    }

    std::istringstream line_stream(normalized_line);
    std::string ip_address;
    line_stream >> ip_address;
    if (ip_address.empty()) continue;

    const std::string ip_lower = toLowerAscii(ip_address);
    if (ip_lower == "127.0.0.1" || ip_lower == "::1" || ip_lower == "0.0.0.0") {
      // Пропускаем стандартные локальные записи, чтобы убрать шум.
      continue;
    }

    std::string hostname;
    while (line_stream >> hostname) {
      trim(hostname);
      if (hostname.empty()) continue;

      const std::string dedupe_key =
          toLowerAscii(ip_address + "|" + hostname);
      if (!seen.insert(dedupe_key).second) continue;

      const std::string details =
          "hosts=" + resolved_hosts_path->filename().string() + ", ip=" +
          ip_address + ", host=" + hostname;
      addExecutionEvidence(process_data, network_context_key, "Hosts",
                          hosts_timestamp, details);
      collected++;
    }
  }

  logger->info("Hosts: добавлено {} запись(ей)", collected);
}

}  // namespace WindowsDiskAnalysis
