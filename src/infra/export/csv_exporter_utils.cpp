/// @file csv_exporter_utils.cpp
/// @brief Реализация утилит строк и путей для CSV-экспорта.

#include "csv_exporter_utils.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>

#include "common/utils.hpp"
#include "parsers/prefetch/metadata/volume_type.hpp"

using namespace PrefetchAnalysis;

namespace WindowsDiskAnalysis {
namespace CsvExporterUtils {

char toLowerAsciiChar(const unsigned char c) {
  if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
  return static_cast<char>(c);
}

std::string toLowerAscii(std::string value) {
  std::ranges::transform(value, value.begin(),
                         [](const unsigned char c) { return toLowerAsciiChar(c); });
  return value;
}

std::string normalizePath(const std::string& path) {
  if (path.empty()) return "";

  std::string result = path;

  trim(result);
  if (!result.empty() && (result.front() == '"' || result.front() == '\'')) {
    const char quote = result.front();
    if (const size_t quote_end = result.find(quote, 1);
        quote_end != std::string::npos) {
      result = result.substr(1, quote_end - 1);
    }
  } else {
    const std::string lowered = toLowerAscii(result);
    for (const std::string ext : {".exe", ".dll", ".sys", ".com", ".bat",
                                  ".cmd"}) {
      if (const size_t ext_pos = lowered.find(ext);
          ext_pos != std::string::npos) {
        result = result.substr(0, ext_pos + ext.size());
        break;
      }
    }
  }

  std::ranges::replace(result, '/', '\\');

  auto start = result.find_first_not_of(" \"");
  auto end = result.find_last_not_of(" \"");

  if (start == std::string::npos || end == std::string::npos) return "";

  return result.substr(start, end - start + 1);
}

bool isSyntheticNetworkContextKey(const std::string& path) {
  std::string lowered = toLowerAscii(path);
  trim(lowered);
  return lowered == "__network_context__";
}

std::string getFilenameFromPath(const std::string& path) {
  if (path.empty()) return {};
  std::string normalized = path;
  std::ranges::replace(normalized, '\\', '/');
  const size_t sep_pos = normalized.find_last_of('/');
  if (sep_pos == std::string::npos) return normalized;
  return normalized.substr(sep_pos + 1);
}

std::string volumeTypeToString(const uint32_t type) {
  switch (static_cast<VolumeType>(type)) {
    case VolumeType::FIXED:
      return "FIXED";
    case VolumeType::REMOVABLE:
      return "REMOVABLE";
    case VolumeType::NETWORK:
      return "NETWORK";
    case VolumeType::OPTICAL:
      return "CDROM";
    case VolumeType::RAMDISK:
      return "RAM";
    case VolumeType::SYSTEM:
      return "SYSTEM";
    case VolumeType::TEMPORARY:
      return "TEMPORARY";
    case VolumeType::VIRTUAL:
      return "VIRTUAL";
    default:
      return "UNKNOWN";
  }
}

std::string normalizeEvidenceSource(std::string source) {
  trim(source);
  if (source.empty()) return {};

  static const std::unordered_map<std::string, std::string_view>
      kCanonicalEvidenceSources = {
          {"prefetch", "Prefetch"},
          {"eventlog", "EventLog"},
          {"event log", "EventLog"},
          {"amcache", "Amcache"},
          {"autorun", "Autorun"},
          {"networkevent", "NetworkEvent"},
          {"network event", "NetworkEvent"},
          {"networkprofile", "NetworkProfile"},
          {"network profile", "NetworkProfile"},
          {"firewallrule", "FirewallRule"},
          {"firewall rule", "FirewallRule"},
          {"service", "Service"},
          {"services", "Service"},
          {"hosts", "Hosts"},
          {"hostsfile", "Hosts"},
          {"hosts file", "Hosts"},
          {"userassist", "UserAssist"},
          {"runmru", "RunMRU"},
          {"featureusage", "FeatureUsage"},
          {"feature usage", "FeatureUsage"},
          {"bam", "BAM"},
          {"dam", "DAM"},
          {"shimcache", "ShimCache"},
          {"recentapps", "RecentApps"},
          {"recent apps", "RecentApps"},
          {"taskscheduler", "TaskScheduler"},
          {"task scheduler", "TaskScheduler"},
          {"ifeo", "IFEO"},
          {"wer", "WER"},
          {"timeline", "Timeline"},
          {"bits", "BITS"},
          {"wmirepository", "WMIRepository"},
          {"wmi repository", "WMIRepository"},
          {"windowssearch", "WindowsSearch"},
          {"windows search", "WindowsSearch"},
          {"jumplist", "JumpList"},
          {"jump list", "JumpList"},
          {"lnkrecent", "LNKRecent"},
          {"lnk recent", "LNKRecent"},
          {"srum", "SRUM"},
          {"usn", "USN"},
          {"$logfile", "$LogFile"},
          {"logfile", "$LogFile"},
          {"vss", "VSS"},
          {"pagefile", "Pagefile"},
          {"memory", "Memory"},
          {"unallocated", "Unallocated"},
      };

  const std::string lowered = toLowerAscii(source);
  const auto it = kCanonicalEvidenceSources.find(lowered);
  if (it != kCanonicalEvidenceSources.end()) {
    return std::string(it->second);
  }
  return source;
}

}  // namespace CsvExporterUtils
}  // namespace WindowsDiskAnalysis
