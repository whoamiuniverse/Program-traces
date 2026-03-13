/// @file jump_lists_collector.cpp
/// @brief Реализация JumpListsCollector.
#include "jump_lists_collector.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/lnk/lnk_parser.hpp"
#include "parsers/ole/compound_file.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::fileTimeToUtcString;
using EvidenceUtils::toLowerAscii;

namespace {

constexpr uint8_t kLnkHeaderSignature[] = {
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

std::optional<std::vector<uint8_t>> readBinaryFile(const fs::path& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  if (size <= 0) {
    return std::nullopt;
  }
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(static_cast<std::size_t>(size));
  if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
    return std::nullopt;
  }
  return data;
}

std::vector<std::vector<uint8_t>> extractCustomDestinationLnkBlobs(
    const std::vector<uint8_t>& data) {
  std::vector<std::vector<uint8_t>> blobs;
  auto it = std::search(data.begin(), data.end(),
                        std::begin(kLnkHeaderSignature),
                        std::end(kLnkHeaderSignature));
  while (it != data.end()) {
    const auto next = std::search(std::next(it), data.end(),
                                  std::begin(kLnkHeaderSignature),
                                  std::end(kLnkHeaderSignature));
    blobs.emplace_back(it, next);
    it = next;
  }
  return blobs;
}

}  // namespace

void JumpListsCollector::collect(const ExecutionEvidenceContext& ctx,
                                 std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_jump_lists) return;
  const auto logger = GlobalLogger::get();
  const std::size_t max_bytes = toByteLimit(ctx.config.binary_scan_max_mb);
  std::size_t collected = 0;
  std::error_code ec;

  auto process_jump_dir = [&](const fs::path& jump_dir) {
    ec.clear();
    if (!fs::exists(jump_dir, ec) || ec || !fs::is_directory(jump_dir, ec) || ec) {
      return;
    }

    for (const auto& file_entry : fs::directory_iterator(jump_dir, ec)) {
      if (ec) break;
      if (!file_entry.is_regular_file()) continue;

      const std::string ext = toLowerAscii(file_entry.path().extension().string());
      if (ext != ".automaticdestinations-ms" && ext != ".customdestinations-ms") {
        continue;
      }

      std::vector<std::string> candidates;
      std::string timestamp = fileTimeToUtcString(
          fs::last_write_time(file_entry.path(), ec));
      std::string details = "jump=" + file_entry.path().filename().string();

      if (ext == ".automaticdestinations-ms") {
        if (const auto streams =
                CompoundFile::readStreams(file_entry.path().string());
            streams.has_value()) {
          for (const auto& stream : *streams) {
            if (auto parsed = parseLnkBytes(stream.data); parsed.has_value()) {
              const std::string candidate =
                  parsed->target_path.empty() ? parsed->relative_path
                                              : parsed->target_path;
              if (candidate.empty()) {
                continue;
              }

              candidates.push_back(candidate);
              details = "jump=" + file_entry.path().filename().string() +
                        ", stream=" + stream.name;
              if (!parsed->write_time.empty() && parsed->write_time != "N/A") {
                timestamp = parsed->write_time;
              }
            }
          }
        }
      } else if (const auto bytes = readBinaryFile(file_entry.path());
                 bytes.has_value()) {
        for (const auto& blob : extractCustomDestinationLnkBlobs(*bytes)) {
          if (auto parsed = parseLnkBytes(blob); parsed.has_value()) {
            const std::string candidate =
                parsed->target_path.empty() ? parsed->relative_path
                                            : parsed->target_path;
            if (candidate.empty()) {
              continue;
            }

            candidates.push_back(candidate);
            if (!parsed->write_time.empty() && parsed->write_time != "N/A") {
              timestamp = parsed->write_time;
            }
          }
        }
      }

      if (candidates.empty()) {
        collectFileCandidates(file_entry.path(), max_bytes,
                              ctx.config.max_candidates_per_source, candidates);
      }

      for (const auto& executable : candidates) {
        addExecutionEvidence(process_data, executable, "JumpList", timestamp,
                             details);
        collected++;
      }
    }
  };

  const fs::path users_root = fs::path(ctx.disk_root) / "Users";
  if (!fs::exists(users_root, ec) || ec || !fs::is_directory(users_root, ec) ||
      ec) {
    return;
  }

  for (const auto& user_entry : fs::directory_iterator(users_root, ec)) {
    if (ec) break;
    if (!user_entry.is_directory()) continue;
    process_jump_dir(user_entry.path() / ctx.config.jump_auto_suffix);
    process_jump_dir(user_entry.path() / ctx.config.jump_custom_suffix);
  }

  logger->info("Jump Lists: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
