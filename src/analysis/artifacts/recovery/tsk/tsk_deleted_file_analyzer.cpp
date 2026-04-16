/// @file tsk_deleted_file_analyzer.cpp
/// @brief Recovery analyzer using The Sleuth Kit for deleted file extraction.

#include "tsk_deleted_file_analyzer.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBTSK) && PROGRAM_TRACES_HAVE_LIBTSK
#include <tsk/libtsk.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::toByteLimit;

// ---------------------------------------------------------------------------
// Forensic file extension filter
// ---------------------------------------------------------------------------

/// @brief Returns true if the filename extension indicates a forensic artifact.
bool isForensicExtension(const std::string_view name) {
  if (name.size() < 3) return false;

  // Find last dot.
  const auto dot_pos = name.rfind('.');
  if (dot_pos == std::string_view::npos || dot_pos + 1 >= name.size()) return false;

  std::string ext;
  ext.reserve(name.size() - dot_pos);
  for (auto i = dot_pos; i < name.size(); ++i)
    ext += static_cast<char>(std::tolower(static_cast<unsigned char>(name[i])));

  // Execution artifacts.
  if (ext == ".pf")    return true;  // Prefetch
  if (ext == ".evtx")  return true;  // Event Log
  if (ext == ".evt")   return true;  // Legacy Event Log
  if (ext == ".lnk")   return true;  // Shell Link
  if (ext == ".job")   return true;  // Task Scheduler 1.0

  // Database artifacts.
  if (ext == ".dat")   return true;  // SRUM, qmgr, etc.
  if (ext == ".db")    return true;  // SQLite databases
  if (ext == ".sqlite") return true;

  // Registry.
  if (ext == ".log1")  return true;  // Registry transaction log
  if (ext == ".log2")  return true;
  if (ext == ".blf")   return true;  // CLFS

  // WER.
  if (ext == ".wer")   return true;

  // Executables (for MFT-based evidence).
  if (ext == ".exe")   return true;
  if (ext == ".dll")   return true;
  if (ext == ".sys")   return true;
  if (ext == ".bat")   return true;
  if (ext == ".cmd")   return true;
  if (ext == ".ps1")   return true;
  if (ext == ".vbs")   return true;
  if (ext == ".js")    return true;
  if (ext == ".msi")   return true;
  if (ext == ".scr")   return true;

  return false;
}

/// @brief Returns true if the file name (without extension) matches well-known
/// artifact file names that lack a distinctive extension.
bool isForensicFileName(const std::string_view name) {
  std::string lower;
  lower.reserve(name.size());
  for (char c : name)
    lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  if (lower == "$mft")          return true;
  if (lower == "$usnjrnl")      return true;
  if (lower == "ntuser.dat")    return true;
  if (lower == "sam")           return true;
  if (lower == "system")        return true;
  if (lower == "software")      return true;
  if (lower == "security")      return true;
  if (lower == "srudb.dat")     return true;
  if (lower == "objects.data")  return true;
  if (lower == "amcache.hve")   return true;
  if (lower == "syscache.hve")  return true;

  // qmgr BITS files.
  if (lower.starts_with("qmgr") && lower.ends_with(".dat")) return true;

  return false;
}

bool isForensicArtifact(const std::string_view name) {
  return isForensicExtension(name) || isForensicFileName(name);
}

#if defined(PROGRAM_TRACES_HAVE_LIBTSK) && PROGRAM_TRACES_HAVE_LIBTSK

// ---------------------------------------------------------------------------
// RAII wrappers for TSK handles
// ---------------------------------------------------------------------------

struct TskImgDeleter {
  void operator()(TSK_IMG_INFO* p) const { if (p) tsk_img_close(p); }
};
struct TskFsDeleter {
  void operator()(TSK_FS_INFO* p) const { if (p) tsk_fs_close(p); }
};
struct TskFsFileDeleter {
  void operator()(TSK_FS_FILE* p) const { if (p) tsk_fs_file_close(p); }
};

using TskImgPtr  = std::unique_ptr<TSK_IMG_INFO, TskImgDeleter>;
using TskFsPtr   = std::unique_ptr<TSK_FS_INFO, TskFsDeleter>;
using TskFilePtr = std::unique_ptr<TSK_FS_FILE, TskFsFileDeleter>;

// ---------------------------------------------------------------------------
// Directory walk callback context
// ---------------------------------------------------------------------------

struct DirWalkContext {
  TSK_FS_INFO*                      fs     = nullptr;
  std::vector<RecoveryEvidence>*    results = nullptr;
  std::unordered_set<std::string>*  dedup  = nullptr;
  std::size_t                       max_candidates = 0;
  std::size_t                       max_file_read  = 0;
};

/// @brief Reconstructs the full path of a TSK_FS_FILE from its name + parent inode.
std::string tskBuildPath(TSK_FS_INFO* fs, TSK_FS_FILE* file) {
  if (!file || !file->name || !file->name->name) return {};

  std::string name(file->name->name);

  // Walk up parent inodes (limited depth to prevent loops).
  TSK_INUM_T parent = file->name->par_addr;
  constexpr int kMaxDepth = 32;
  std::unordered_set<TSK_INUM_T> visited;
  std::string path = name;

  for (int depth = 0; depth < kMaxDepth; ++depth) {
    if (parent == 0 || parent == fs->root_inum) {
      path = "\\" + path;
      break;
    }
    if (visited.count(parent)) break;
    visited.insert(parent);

    TSK_FS_FILE* parent_file = tsk_fs_file_open_meta(fs, nullptr, parent);
    if (!parent_file) break;

    // Find the default $FILE_NAME for this inode.
    std::string segment;
    if (parent_file->name && parent_file->name->name) {
      segment = parent_file->name->name;
    } else {
      // Fall back to listing the parent's parent directory.
      segment = "[inode:" + std::to_string(parent) + "]";
    }

    TSK_INUM_T next_parent = 0;
    if (parent_file->name) next_parent = parent_file->name->par_addr;
    tsk_fs_file_close(parent_file);

    path = segment + "\\" + path;
    if (next_parent == parent) break;
    parent = next_parent;
  }

  return path;
}

/// @brief Reads up to @p max_bytes of a deleted file's default $DATA attribute.
std::vector<uint8_t> tskReadFileContent(TSK_FS_FILE* file, std::size_t max_bytes) {
  if (!file || !file->meta) return {};

  const TSK_OFF_T file_size = file->meta->size;
  if (file_size <= 0) return {};

  const std::size_t read_size = std::min<std::size_t>(
      static_cast<std::size_t>(file_size), max_bytes);

  std::vector<uint8_t> buffer(read_size);
  const ssize_t actual = tsk_fs_file_read(
      file, 0, reinterpret_cast<char*>(buffer.data()),
      read_size, TSK_FS_FILE_READ_FLAG_NONE);

  if (actual <= 0) return {};
  buffer.resize(static_cast<std::size_t>(actual));
  return buffer;
}

/// @brief TSK directory walk callback. Called for each file/directory entry.
TSK_WALK_RET_ENUM dirWalkCallback(TSK_FS_FILE* file,
                                   const char* /*path*/,
                                   void* context_ptr) {
  auto* ctx = static_cast<DirWalkContext*>(context_ptr);
  if (ctx->results->size() >= ctx->max_candidates) return TSK_WALK_STOP;

  if (!file || !file->name || !file->name->name) return TSK_WALK_CONT;
  if (!file->meta) return TSK_WALK_CONT;

  // Skip directories, ".", "..", and system metadata files.
  if (file->meta->type == TSK_FS_META_TYPE_DIR) return TSK_WALK_CONT;
  if (file->name->name[0] == '.' &&
      (file->name->name[1] == '\0' ||
       (file->name->name[1] == '.' && file->name->name[2] == '\0')))
    return TSK_WALK_CONT;

  const std::string_view fname(file->name->name);

  // Only process deleted files with forensic-relevant names,
  // OR allocated files that are forensic artifacts (for completeness).
  const bool is_deleted = (file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) != 0;
  if (!isForensicArtifact(fname)) return TSK_WALK_CONT;

  const std::string full_path = tskBuildPath(ctx->fs, file);
  const std::string display = full_path.empty() ? std::string(fname) : full_path;

  std::ostringstream details;
  details << "inode=" << file->name->meta_addr
          << " flags=" << (is_deleted ? "deleted" : "allocated")
          << " size=" << (file->meta->size > 0 ? file->meta->size : 0);

  RecoveryEvidence ev;
  ev.executable_path = display;
  ev.source          = "TSK";
  ev.recovered_from  = is_deleted ? "TSK(deleted)" : "TSK(allocated)";
  ev.details         = details.str();

  // Try to read the file content and extract executable paths from it.
  if (is_deleted && file->meta->size > 0) {
    const auto content = tskReadFileContent(file, ctx->max_file_read);
    if (!content.empty()) {
      const auto candidates = EvidenceUtils::extractExecutableCandidatesFromBinary(
          content, 10);
      if (!candidates.empty()) {
        std::ostringstream extra;
        extra << " recovered_content=" << content.size() << "B";
        extra << " exe_candidates=[";
        for (std::size_t i = 0; i < candidates.size() && i < 5; ++i) {
          if (i) extra << "|";
          extra << candidates[i];
        }
        extra << "]";
        ev.details += extra.str();
      }
    }
  }

  const std::string key = ev.executable_path + "|" + ev.recovered_from;
  if (ctx->dedup->insert(key).second)
    ctx->results->push_back(std::move(ev));

  return TSK_WALK_CONT;
}

// ---------------------------------------------------------------------------
// Unallocated block scan
// ---------------------------------------------------------------------------

struct BlkWalkContext {
  std::vector<RecoveryEvidence>*   results       = nullptr;
  std::unordered_set<std::string>* dedup         = nullptr;
  std::size_t                      max_candidates = 0;
  std::size_t                      bytes_scanned  = 0;
  std::size_t                      max_bytes      = 0;
  std::vector<uint8_t>             buffer;        ///< Accumulation buffer.
  uint64_t                         buffer_offset  = 0;
};

TSK_WALK_RET_ENUM blkWalkCallback(const TSK_FS_BLOCK* block,
                                   void* context_ptr) {
  auto* ctx = static_cast<BlkWalkContext*>(context_ptr);
  if (ctx->results->size() >= ctx->max_candidates) return TSK_WALK_STOP;
  if (ctx->bytes_scanned >= ctx->max_bytes) return TSK_WALK_STOP;

  if (!block || !block->buf) return TSK_WALK_CONT;

  const std::size_t blk_size = static_cast<std::size_t>(block->fs_info->block_size);
  ctx->bytes_scanned += blk_size;

  // Accumulate blocks into a larger buffer for more efficient scanning.
  constexpr std::size_t kScanChunkSize = 256 * 1024;  // 256 KiB

  if (ctx->buffer.empty()) {
    ctx->buffer_offset = static_cast<uint64_t>(block->addr) * blk_size;
  }

  ctx->buffer.insert(ctx->buffer.end(),
                     block->buf, block->buf + blk_size);

  if (ctx->buffer.size() >= kScanChunkSize) {
    auto chunk_ev = RecoveryUtils::scanRecoveryBufferBinary(
        ctx->buffer, "TSK", "TSK(unallocated)", "unalloc_blocks",
        "", ctx->max_candidates - ctx->results->size(),
        ctx->buffer_offset, "tsk_unalloc", 0);

    RecoveryUtils::appendUniqueEvidence(*ctx->results, chunk_ev, *ctx->dedup);
    ctx->buffer.clear();
  }

  return TSK_WALK_CONT;
}

/// @brief Opens a TSK image from a file path.
TskImgPtr openTskImage(const std::string& path) {
  const char* paths[] = {path.c_str()};
  TSK_IMG_INFO* img = tsk_img_open(
      1, paths, TSK_IMG_TYPE_DETECT, 0);
  return TskImgPtr(img);
}

#endif  // PROGRAM_TRACES_HAVE_LIBTSK

}  // namespace

// ---------------------------------------------------------------------------
// TskDeletedFileAnalyzer — public API
// ---------------------------------------------------------------------------

TskDeletedFileAnalyzer::TskDeletedFileAnalyzer(std::string config_path,
                                               std::string image_path)
    : config_path_(std::move(config_path)),
      image_path_(std::move(image_path)) {
  loadConfiguration();
}

void TskDeletedFileAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      max_candidates_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "TskMaxCandidates",
                           static_cast<int>(max_candidates_))));
      max_file_read_bytes_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "TskMaxFileReadMB",
                           static_cast<int>(max_file_read_bytes_ / (1024 * 1024))))) *
          1024 * 1024;
      max_unalloc_scan_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "TskMaxUnallocScanMB",
                           static_cast<int>(max_unalloc_scan_mb_))));
      const std::string img = config.getString("Recovery", "TskImagePath", "");
      if (!img.empty() && image_path_.empty()) image_path_ = img;

      for (const std::string& key : {"EnableTskRecovery", "TskScanUnallocated"}) {
        if (config.hasKey("Recovery", key)) {
          logger->warn(
              "Параметр [Recovery]/{} игнорируется: модуль TSK всегда активен",
              key);
        }
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки TskDeletedFileAnalyzer");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Ошибка чтения [Recovery] для TSK: {}", e.what());
  }
}

std::vector<RecoveryEvidence> TskDeletedFileAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

#if !defined(PROGRAM_TRACES_HAVE_LIBTSK) || !PROGRAM_TRACES_HAVE_LIBTSK
  logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
              spdlog::level::debug,
              "TSK recovery: libtsk недоступен в текущей сборке");
  static_cast<void>(disk_root);
  return {};
#else
  // Determine image path: CLI override > config > disk_root.
  const std::string img_path = image_path_.empty() ? disk_root : image_path_;
  if (img_path.empty()) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "TSK recovery: не задан путь к образу или диску");
    return {};
  }

  // Open image.
  auto img = openTskImage(img_path);
  if (!img) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "TSK recovery: не удалось открыть образ \"{}\"", img_path);
    return {};
  }

  // Open filesystem (offset 0 = first partition or whole-disk image).
  TskFsPtr fs(tsk_fs_open_img(img.get(), 0, TSK_FS_TYPE_DETECT));
  if (!fs) {
    // Try common partition offsets for MBR (63*512, 2048*512).
    for (TSK_OFF_T offset : {static_cast<TSK_OFF_T>(63 * 512),
                              static_cast<TSK_OFF_T>(2048 * 512),
                              static_cast<TSK_OFF_T>(1048576)}) {
      fs.reset(tsk_fs_open_img(img.get(), offset, TSK_FS_TYPE_DETECT));
      if (fs) break;
    }
    if (!fs) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "TSK recovery: не удалось открыть файловую систему в \"{}\"",
                  img_path);
      return {};
    }
  }

  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;

  // ---- Phase 1: Walk directory tree for deleted forensic files ----
  {
    DirWalkContext ctx;
    ctx.fs             = fs.get();
    ctx.results        = &results;
    ctx.dedup          = &dedup;
    ctx.max_candidates = max_candidates_;
    ctx.max_file_read  = max_file_read_bytes_;

    const int walk_flags =
        TSK_FS_DIR_WALK_FLAG_ALLOC |
        TSK_FS_DIR_WALK_FLAG_UNALLOC |
        TSK_FS_DIR_WALK_FLAG_RECURSE;

    tsk_fs_dir_walk(
        fs.get(), fs->root_inum,
        static_cast<TSK_FS_DIR_WALK_FLAG_ENUM>(walk_flags),
        dirWalkCallback, &ctx);
  }

  const std::size_t dir_walk_count = results.size();

  // ---- Phase 2: Scan unallocated blocks for signature carving ----
  std::size_t unalloc_count = 0;
  if (results.size() < max_candidates_) {
    BlkWalkContext bctx;
    bctx.results        = &results;
    bctx.dedup          = &dedup;
    bctx.max_candidates = max_candidates_;
    bctx.max_bytes      = toByteLimit(max_unalloc_scan_mb_);

    tsk_fs_block_walk(
        fs.get(), fs->first_block, fs->last_block,
        static_cast<TSK_FS_BLOCK_WALK_FLAG_ENUM>(TSK_FS_BLOCK_WALK_FLAG_UNALLOC),
        blkWalkCallback, &bctx);

    // Flush remaining buffer.
    if (!bctx.buffer.empty() && results.size() < max_candidates_) {
      auto tail_ev = RecoveryUtils::scanRecoveryBufferBinary(
          bctx.buffer, "TSK", "TSK(unallocated)", "unalloc_blocks",
          "", max_candidates_ - results.size(),
          bctx.buffer_offset, "tsk_unalloc_tail", 0);
      appendUniqueEvidence(results, tail_ev, dedup);
    }

    unalloc_count = results.size() - dir_walk_count;
  }

  logger->info("Recovery(TSK): deleted_files={} unallocated={} total={}",
               dir_walk_count, unalloc_count, results.size());
  return results;
#endif
}

}  // namespace WindowsDiskAnalysis
