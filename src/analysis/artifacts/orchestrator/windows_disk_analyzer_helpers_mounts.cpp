/// @file windows_disk_analyzer_helpers_mounts.cpp
/// @brief Helper-функции оркестратора для работы с монтированиями и `disk_root`.

#include "windows_disk_analyzer_helpers.hpp"

#include <filesystem>
#include <unordered_set>

#include "infra/logging/logger.hpp"

#ifdef __APPLE__
#include <sys/mount.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <mntent.h>
#include <unistd.h>
#endif

namespace WindowsDiskAnalysis::Orchestrator::Detail {

namespace fs = std::filesystem;

std::string resolveMountedPath(const std::string& device_path) {
#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    if (device_path == mounts[i].f_mntfromname) {
      return mounts[i].f_mntonname;
    }
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (device_path == entry->mnt_fsname) {
        const std::string mount_point = entry->mnt_dir;
        endmntent(mounts_file);
        return mount_point;
      }
    }
    endmntent(mounts_file);
  }
#endif
  return {};
}

std::vector<MountedRootInfo> listMountedRoots() {
  std::vector<MountedRootInfo> roots;
  std::unordered_set<std::string> unique_roots;
  const auto logger = GlobalLogger::get();

  auto append_root = [&](const std::string& root_path_raw,
                         const std::string& device_path_raw) {
    if (root_path_raw.empty()) return;
    const std::string root_path = ensureTrailingSlash(root_path_raw);
    std::error_code ec;
    if (!fs::is_directory(root_path, ec) || ec) {
      if (ec) {
        logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, "Пропуск точки монтирования \"{}\": {}", root_path_raw,
                      formatFilesystemError(ec));
      }
      return;
    }
    if (unique_roots.insert(root_path).second) {
      roots.push_back({device_path_raw, root_path});
    }
  };

#ifdef __APPLE__
  struct statfs* mounts = nullptr;
  const int mounts_count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int i = 0; i < mounts_count; ++i) {
    append_root(mounts[i].f_mntonname, mounts[i].f_mntfromname);
  }
#elif __linux__
  if (FILE* mounts_file = setmntent("/proc/self/mounts", "r");
      mounts_file != nullptr) {
    while (const mntent* entry = getmntent(mounts_file)) {
      if (entry != nullptr && entry->mnt_dir != nullptr) {
        append_root(entry->mnt_dir,
                    entry->mnt_fsname != nullptr ? entry->mnt_fsname : "");
      }
    }
    endmntent(mounts_file);
  }
#endif

  return roots;
}

std::string normalizeDiskRoot(std::string disk_root) {
  if (isAutoDiskRootValue(disk_root)) {
    return {};
  }

  std::error_code ec;
  if (fs::is_directory(disk_root, ec) && !ec) {
    return ensureTrailingSlash(std::move(disk_root));
  }

  ec.clear();
  const bool is_device = fs::is_block_file(disk_root, ec) ||
                         fs::is_character_file(disk_root, ec);
  if (is_device && !ec) {
    const std::string mount_point = resolveMountedPath(disk_root);
    if (mount_point.empty()) {
      throw DiskNotMountedException(disk_root);
    }
    return ensureTrailingSlash(mount_point);
  }

  ec.clear();
  if (!fs::exists(disk_root, ec) || ec) {
    throw InvalidDiskRootException(
        disk_root, "путь не существует или недоступен для чтения");
  }

  throw InvalidDiskRootException(
      disk_root,
      "ожидался путь к каталогу (точке монтирования) или блочному устройству");
}

}  // namespace WindowsDiskAnalysis::Orchestrator::Detail
