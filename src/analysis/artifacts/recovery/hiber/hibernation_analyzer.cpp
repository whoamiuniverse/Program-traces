/// @file hibernation_analyzer.cpp
/// @brief Реализация анализатора `hiberfil.sys`.

#include "hibernation_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <unordered_set>
#include <utility>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/recovery/recovery_utils.hpp"
#include "common/utils.hpp"
#include "infra/config/config.hpp"
#include "infra/logging/logger.hpp"

#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
#include <libhibr.h>
#endif

namespace WindowsDiskAnalysis {
namespace {

namespace fs = std::filesystem;
using RecoveryUtils::appendUniqueEvidence;
using RecoveryUtils::findPathCaseInsensitive;
using RecoveryUtils::scanRecoveryBufferBinary;
using RecoveryUtils::scanRecoveryFileBinary;
using RecoveryUtils::toByteLimit;

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

inline uint32_t readU32Le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t readU64Le(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
  return v;
}

// ---------------------------------------------------------------------------
// EPROCESS pool-tag scanner (0.2.3)
// ---------------------------------------------------------------------------
//
// Windows kernel allocates EPROCESS blocks from the NonPagedPool.
// The pool block header includes a 4-byte tag. The EPROCESS tag is "Proc"
// (bytes: 50 72 6F 63). Because field offsets vary by OS version we use
// a heuristic: scan for the tag, then try several well-known ImageFileName
// offsets (process name is a null-terminated ASCII string ≤ 15 chars).
//
// Known ImageFileName offsets relative to the start of EPROCESS structure
// (which is typically pool_header_size + OBJECT_HEADER_size after the tag):
//   Win7  x64: 0x2E0
//   Win8  x64: 0x438
//   Win10 x64: 0x450 (early), 0x5A8 (later)
//   Win10 x86: 0x174
// We try them all and accept any that yields a plausible process name.

struct EprocessCandidate {
  std::string image_name;   ///< ImageFileName (≤15 ASCII chars).
  uint64_t    pid;          ///< UniqueProcessId (best-effort).
  std::size_t pool_offset;  ///< Byte offset of pool tag in image.
};

/// @brief Checks whether @p name looks like a valid Windows process name.
bool isValidProcessName(const char* p, std::size_t max_len) {
  if (max_len == 0 || p[0] == '\0') return false;
  std::size_t len = 0;
  while (len < max_len && p[len] != '\0') {
    const unsigned char c = static_cast<unsigned char>(p[len]);
    if (c < 0x20 || c > 0x7E) return false;  // non-printable
    ++len;
  }
  if (len < 2 || len >= max_len) return false;

  std::string name(p, len);
  const std::string lowered = to_lower(name);
  const auto has_allowed_suffix = [&](const std::string& text) {
    return ends_with(text, ".exe") || ends_with(text, ".com") ||
           ends_with(text, ".sys") || ends_with(text, ".dll");
  };
  const auto is_kernel_name = [&](const std::string& text) {
    return text == "system" || text == "registry" || text == "idle" ||
           text == "memcompression";
  };

  if (!has_allowed_suffix(lowered) && !is_kernel_name(lowered)) {
    return false;
  }

  for (const char ch : name) {
    const auto c = static_cast<unsigned char>(ch);
    if (std::isalnum(c) != 0) continue;
    if (c == '.' || c == '_' || c == '-') continue;
    return false;
  }
  return true;
}

/// @brief Scans @p data for EPROCESS candidates using pool-tag heuristics.
std::vector<EprocessCandidate> scanForEprocess(const std::vector<uint8_t>& data) {
  // Pool tag "Proc" = 50 72 6F 63
  static const uint8_t kTag[4] = {0x50, 0x72, 0x6F, 0x63};
  // Offsets of ImageFileName from the pool-tag byte (empirical).
  // We add small OBJECT_HEADER/pool-header deltas here.
  static const std::size_t kImgOffsets[] = {
      0x2F0, 0x300, 0x448, 0x460, 0x5B8, 0x5C0, 0x184, 0x190};
  // UniqueProcessId is typically 8 bytes before ImageFileName on x64
  // or 4 bytes before on x86. Try both.
  static const int kPidDeltas[] = {-8, -4, +8, +4};

  std::vector<EprocessCandidate> results;
  const std::size_t sz = data.size();
  if (sz < 64) return results;

  for (std::size_t i = 0; i + 4 <= sz; ++i) {
    if (std::memcmp(data.data() + i, kTag, 4) != 0) continue;

    for (std::size_t img_off : kImgOffsets) {
      const std::size_t img_pos = i + img_off;
      if (img_pos + 16 > sz) continue;

      const char* name_ptr = reinterpret_cast<const char*>(data.data() + img_pos);
      if (!isValidProcessName(name_ptr, 15)) continue;

      EprocessCandidate cand;
      cand.image_name  = std::string(name_ptr, strnlen(name_ptr, 15));
      cand.pool_offset = i;
      cand.pid         = 0;

      // Try to read PID
      for (int delta : kPidDeltas) {
        const auto pid_pos = static_cast<std::ptrdiff_t>(img_pos) + delta;
        if (pid_pos < 0 || static_cast<std::size_t>(pid_pos) + 8 > sz) continue;
        const uint64_t pid_val = readU64Le(data.data() + pid_pos);
        // PIDs on Windows are multiples of 4, non-zero.  Win10 21H2+ can
        // assign PIDs > 65536 on servers with long uptime; cap at 4M.
        if (pid_val > 0 && pid_val < 4194304 && (pid_val & 0x3) == 0) {
          cand.pid = pid_val;
          break;
        }
      }
      results.push_back(std::move(cand));
      break;  // one candidate per tag hit is enough
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Network endpoint pool-tag scanner (0.2.5)
// ---------------------------------------------------------------------------
//
// TCP endpoints:  pool tag "TcpE" (54 63 70 45)
// UDP endpoints:  pool tag "UdpA" (55 64 70 41)
//
// Layout is OS-version specific; we use heuristics to extract IP:port.

struct NetworkEndpointCandidate {
  std::string protocol;    ///< "TCP" or "UDP"
  std::string local_addr;  ///< x.x.x.x:port
  std::string remote_addr; ///< x.x.x.x:port (TCP only)
  std::size_t pool_offset;
};

/// @brief Formats a raw IPv4 address + port from a buffer position.
static std::string formatIpPort(const uint8_t* addr, uint16_t port) {
  std::ostringstream ss;
  ss << static_cast<int>(addr[0]) << '.'
     << static_cast<int>(addr[1]) << '.'
     << static_cast<int>(addr[2]) << '.'
     << static_cast<int>(addr[3]) << ':' << port;
  return ss.str();
}

/// @brief Returns true if @p addr looks like a plausible unicast IPv4 address.
static bool isPlausibleIpv4(const uint8_t* addr) {
  // Reject 0.0.0.0 and 255.255.255.255
  const uint32_t v = readU32Le(addr);
  if (v == 0 || v == 0xFFFFFFFFU) return false;
  // Reject loopback, multicast and link-local APIPA ranges to reduce noise.
  if (addr[0] == 127) return false;
  if (addr[0] >= 224) return false;
  if (addr[0] == 169 && addr[1] == 254) return false;
  return true;
}

std::vector<NetworkEndpointCandidate> scanForNetworkEndpoints(
    const std::vector<uint8_t>& data) {
  // TcpE = 54 63 70 45, UdpA = 55 64 70 41
  static const struct { const uint8_t tag[4]; const char* proto; } kTags[] = {
      {{0x54, 0x63, 0x70, 0x45}, "TCP"},
      {{0x55, 0x64, 0x70, 0x41}, "UDP"},
  };
  // Typical offsets for local IPv4 and port from pool tag start.
  // These are heuristic and cover Win7-Win10 x64.
  static const std::size_t kLocalIpOffsets[]  = {0x18, 0x20, 0x28, 0x30};
  static const std::size_t kLocalPrtOffsets[] = {0x16, 0x1E, 0x26, 0x2E};
  static const std::size_t kRemoteIpOffsets[] = {0x1C, 0x24, 0x2C, 0x34};
  static const std::size_t kRemotePrtOffsets[]= {0x1A, 0x22, 0x2A, 0x32};

  std::vector<NetworkEndpointCandidate> results;
  const std::size_t sz = data.size();
  if (sz < 64) return results;

  for (const auto& tag_desc : kTags) {
    for (std::size_t i = 0; i + 4 <= sz; ++i) {
      if (std::memcmp(data.data() + i, tag_desc.tag, 4) != 0) continue;

      for (std::size_t k = 0; k < 4; ++k) {
        const std::size_t lip_pos = i + kLocalIpOffsets[k];
        const std::size_t lpt_pos = i + kLocalPrtOffsets[k];
        if (lip_pos + 4 > sz || lpt_pos + 2 > sz) continue;

        const uint8_t* lip = data.data() + lip_pos;
        if (!isPlausibleIpv4(lip)) continue;

        // Port bytes are big-endian in INET structures
        const uint16_t lport = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[lpt_pos]) << 8) | data[lpt_pos + 1]);
        if (lport == 0) continue;

        NetworkEndpointCandidate ep;
        ep.protocol    = tag_desc.proto;
        ep.pool_offset = i;
        ep.local_addr  = formatIpPort(lip, lport);

        if (std::string_view(tag_desc.proto) == "TCP") {
          const std::size_t rip_pos = i + kRemoteIpOffsets[k];
          const std::size_t rpt_pos = i + kRemotePrtOffsets[k];
          if (rip_pos + 4 <= sz && rpt_pos + 2 <= sz) {
            const uint8_t* rip = data.data() + rip_pos;
            if (isPlausibleIpv4(rip)) {
              const uint16_t rport = static_cast<uint16_t>(
                  (static_cast<uint16_t>(data[rpt_pos]) << 8) | data[rpt_pos + 1]);
              if (rport != 0) ep.remote_addr = formatIpPort(rip, rport);
            }
          }
        }
        results.push_back(std::move(ep));
        break;  // one endpoint per tag hit
      }
    }
  }
  return results;
}

/// @brief Формирует normalized details для EPROCESS evidence.
std::string buildEprocessDetails(const std::size_t pool_offset,
                                 const uint64_t pid,
                                 std::string_view channel) {
  std::ostringstream details;
  details << "artifact=eprocess"
          << " pool_offset=0x" << std::hex << pool_offset;
  if (pid != 0) {
    details << " pid=" << std::dec << pid;
  }
  details << " channel=" << channel;
  return details.str();
}

/// @brief Формирует normalized details для network endpoint evidence.
std::string buildEndpointDetails(const NetworkEndpointCandidate& endpoint,
                                 const std::size_t pool_offset,
                                 std::string_view channel) {
  std::ostringstream details;
  details << "artifact=network_endpoint"
          << " protocol=" << to_lower(endpoint.protocol)
          << " local=" << endpoint.local_addr;
  if (!endpoint.remote_addr.empty()) {
    details << " remote=" << endpoint.remote_addr;
  }
  details << " pool_offset=0x" << std::hex << pool_offset
          << " channel=" << channel;
  return details.str();
}

// ---------------------------------------------------------------------------
// libhibr native path (0.2.1)
// ---------------------------------------------------------------------------

struct NativeHiberParseResult {
  bool attempted = false;
  bool success   = false;
  std::vector<RecoveryEvidence> evidence;
};

#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
/// @brief Преобразует объект ошибки libhibr в строку.
std::string toLibhibrErrorMessage(libhibr_error_t* error) {
  if (error == nullptr) return "неизвестная ошибка libhibr";
  std::array<char, 2048> buffer{};
  if (libhibr_error_sprint(error, buffer.data(), buffer.size()) > 0)
    return std::string(buffer.data());
  return "не удалось получить описание ошибки libhibr";
}

/// @brief Выполняет native-скан `hiberfil.sys` через libhibr.
NativeHiberParseResult parseHiberNative(const fs::path& hiber_path,
                                        const std::size_t max_pages,
                                        const std::size_t max_bytes,
                                        const std::size_t max_candidates) {
  NativeHiberParseResult result;
  result.attempted = true;

  const auto logger = GlobalLogger::get();
  libhibr_error_t* error = nullptr;
  if (libhibr_check_file_signature(hiber_path.string().c_str(), &error) != 1) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Hiber(native): сигнатура не распознана для \"{}\": {}",
                hiber_path.string(), toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    return result;
  }
  libhibr_error_free(&error);

  libhibr_file_t* file = nullptr;
  if (libhibr_file_initialize(&file, &error) != 1 || file == nullptr) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Hiber(native): инициализация не удалась: {}",
                toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    return result;
  }
  libhibr_error_free(&error);

  auto close_and_free = [&]() {
    if (file == nullptr) return;
    libhibr_error_t* e = nullptr;
    libhibr_file_close(file, &e);
    libhibr_error_free(&e);
    libhibr_file_free(&file, &e);
    libhibr_error_free(&e);
  };

  const int access_flags = libhibr_get_access_flags_read();
  error = nullptr;
  if (libhibr_file_open(file, hiber_path.string().c_str(), access_flags, &error) != 1) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Hiber(native): не удалось открыть \"{}\": {}",
                hiber_path.string(), toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    close_and_free();
    return result;
  }
  libhibr_error_free(&error);
  result.success = true;

  size64_t media_size = 0;
  if (libhibr_file_get_media_size(file, &media_size, &error) != 1) {
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Hiber(native): не удалось определить размер: {}",
                toLibhibrErrorMessage(error));
    libhibr_error_free(&error);
    close_and_free();
    return result;
  }
  libhibr_error_free(&error);

  constexpr std::size_t kPageSize   = 4096;
  constexpr std::size_t kChunkPages = 16;
  const std::size_t chunk_size = kPageSize * kChunkPages;
  const std::size_t page_limited_bytes = max_pages * kPageSize;
  const std::size_t scan_limit = std::min<std::size_t>(
      max_bytes, std::min<std::size_t>(page_limited_bytes,
                                       static_cast<std::size_t>(media_size)));

  std::vector<uint8_t> chunk(chunk_size);
  std::unordered_set<std::string> dedup;
  std::error_code ec;
  const std::string timestamp =
      EvidenceUtils::fileTimeToUtcString(fs::last_write_time(hiber_path, ec));

  for (std::size_t offset = 0;
       offset < scan_limit && result.evidence.size() < max_candidates;
       offset += chunk_size) {
    const std::size_t to_read = std::min(chunk_size, scan_limit - offset);
    error = nullptr;
    const ssize_t read_size = libhibr_file_read_buffer_at_offset(
        file, chunk.data(), to_read, static_cast<off64_t>(offset), &error);
    if (read_size < 0) {
      logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                  spdlog::level::debug,
                  "Hiber(native): ошибка чтения offset={}: {}", offset,
                  toLibhibrErrorMessage(error));
      libhibr_error_free(&error);
      break;
    }
    libhibr_error_free(&error);
    if (read_size == 0) break;

    const std::size_t n = static_cast<std::size_t>(read_size);
    std::vector<uint8_t> scan_buf(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));

    // --- Binary scan for exe strings ---
    auto string_ev = scanRecoveryBufferBinary(
        scan_buf, "Hiber", "Hiber.native", hiber_path.filename().string(),
        timestamp, max_candidates - result.evidence.size(), offset,
        "hiber_native_chunk", scan_limit);
    appendUniqueEvidence(result.evidence, string_ev, dedup);

    // --- EPROCESS pool-tag scan ---
    if (result.evidence.size() < max_candidates) {
      const auto eprocs = scanForEprocess(scan_buf);
      for (const auto& ep : eprocs) {
        if (result.evidence.size() >= max_candidates) break;
        RecoveryEvidence ev;
        ev.executable_path = ep.image_name;
        ev.source          = "Hiber";
        ev.recovered_from  = "Hiber.eprocess";
        ev.timestamp       = timestamp;
        ev.details         = buildEprocessDetails(offset + ep.pool_offset, ep.pid,
                                                  "native");
        const std::string key = ev.executable_path + "|" + ev.recovered_from + "|" + ev.details;
        if (dedup.insert(key).second)
          result.evidence.push_back(std::move(ev));
      }
    }

    // --- Network endpoint pool-tag scan ---
    if (result.evidence.size() < max_candidates) {
      const auto endpoints = scanForNetworkEndpoints(scan_buf);
      for (const auto& ep : endpoints) {
        if (result.evidence.size() >= max_candidates) break;
        RecoveryEvidence ev;
        ev.executable_path = ep.local_addr;
        ev.source          = "Hiber";
        std::string protocol_token = to_lower(ep.protocol);
        trim(protocol_token);
        if (protocol_token.empty()) {
          protocol_token = "network";
        }
        ev.recovered_from  = "Hiber." + protocol_token + "_endpoint";
        ev.timestamp       = timestamp;
        ev.details         =
            buildEndpointDetails(ep, offset + ep.pool_offset, "native");
        const std::string key = ev.executable_path + "|" + ev.recovered_from;
        if (dedup.insert(key).second)
          result.evidence.push_back(std::move(ev));
      }
    }
  }

  close_and_free();
  return result;
}
#endif  // PROGRAM_TRACES_HAVE_LIBHIBR

// ---------------------------------------------------------------------------
// Binary-fallback Xpress signature check (0.2.2)
// ---------------------------------------------------------------------------
//
// Windows 8+ hiberfil.sys starts with a compressed wake image.
// The Xpress Huffman compressed wrapper begins with the signature
// "HIBR" or has a wake-image page-range table starting with magic 0x53726448
// ("HdrS"). We detect compression and log a note; full decompression
// requires libhibr or ms-compress integration.

bool hiberfil_is_compressed(const std::vector<uint8_t>& prefix) {
  if (prefix.size() < 4) return false;
  // "HIBR" = 48 49 42 52 at offset 0
  if (prefix[0] == 0x48 && prefix[1] == 0x49 &&
      prefix[2] == 0x42 && prefix[3] == 0x52) return true;
  // Wake-image structure: first DWORD is page-range count; second QWORD
  // is a physical memory range. Check for the "Hibr" tag at offset 4.
  if (prefix.size() >= 8 &&
      prefix[4] == 0x48 && prefix[5] == 0x69 &&
      prefix[6] == 0x62 && prefix[7] == 0x72) return true;
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// HibernationAnalyzer — public API
// ---------------------------------------------------------------------------

HibernationAnalyzer::HibernationAnalyzer(std::string config_path)
    : config_path_(std::move(config_path)) {
  loadConfiguration();
}

void HibernationAnalyzer::loadConfiguration() {
  const auto logger = GlobalLogger::get();
  try {
    Config config(config_path_, false, false);
    if (config.hasSection("Recovery")) {
      hiber_max_pages_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "HiberMaxPages",
                           static_cast<int>(hiber_max_pages_))));
      hiber_path_ = config.getString("Recovery", "HiberPath", hiber_path_);
      binary_scan_max_mb_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "BinaryScanMaxMB",
                           static_cast<int>(binary_scan_max_mb_))));
      max_candidates_per_source_ = static_cast<std::size_t>(std::max(
          1, config.getInt("Recovery", "MaxCandidatesPerSource",
                           static_cast<int>(max_candidates_per_source_))));

      for (const std::string& key :
           {"EnableHiber", "EnableNativeHiberParser", "HiberFallbackToBinary"}) {
        if (config.hasKey("Recovery", key)) {
          logger->warn(
              "Параметр [Recovery]/{} игнорируется: модуль Hiber всегда активен",
              key);
        }
      }
    }
  } catch (const std::exception& e) {
    logger->warn("Не удалось загрузить настройки HibernationAnalyzer");
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Ошибка чтения [Recovery] для Hiber: {}", e.what());
  }
}

std::vector<RecoveryEvidence> HibernationAnalyzer::collect(
    const std::string& disk_root) const {
  const auto logger = GlobalLogger::get();

  const std::size_t max_bytes = toByteLimit(binary_scan_max_mb_);
  std::vector<RecoveryEvidence> results;
  std::unordered_set<std::string> dedup;
  std::size_t native_count = 0;
  std::size_t binary_count = 0;

  std::vector<fs::path> candidates;
  if (!hiber_path_.empty()) {
    const fs::path configured(hiber_path_);
    if (configured.is_absolute())
      candidates.push_back(configured);
    else
      candidates.push_back(fs::path(disk_root) / configured);
  }
  candidates.push_back(fs::path(disk_root) / "hiberfil.sys");
  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

  for (const fs::path& candidate : candidates) {
    const auto resolved = findPathCaseInsensitive(candidate);
    if (!resolved.has_value()) continue;

    bool need_binary_fallback = true;
#if defined(PROGRAM_TRACES_HAVE_LIBHIBR) && PROGRAM_TRACES_HAVE_LIBHIBR
    logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                spdlog::level::debug,
                "Hiber(native): включен experimental режим libhibr");
    NativeHiberParseResult native_result =
        parseHiberNative(*resolved, hiber_max_pages_, max_bytes,
                         max_candidates_per_source_);
    native_count += native_result.evidence.size();
    need_binary_fallback =
        !native_result.success || native_result.evidence.empty();
    appendUniqueEvidence(results, native_result.evidence, dedup);
#else
    logger->warn("Hiber(native): libhibr недоступен, используется только "
                 "binary fallback");
    need_binary_fallback = true;
#endif

    if (need_binary_fallback) {
      // Check for Xpress compression before binary scan.
      bool is_compressed = false;
      {
        auto prefix_opt = EvidenceUtils::readFilePrefix(*resolved, 16);
        if (prefix_opt.has_value() && hiberfil_is_compressed(*prefix_opt)) {
          is_compressed = true;
          logger->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION},
                      spdlog::level::debug,
                      "Hiber(binary): файл использует Xpress Huffman-сжатие "
                      "(Windows 8+). Binary scan ограничен несжатым "
                      "заголовком (8 KB).");
        }
      }

      // For compressed hiberfil (Win8+), limit binary scan to the
      // uncompressed header region (first 8 KB) — scanning compressed data
      // produces garbage string-carving results.
      const std::size_t scan_limit =
          is_compressed ? std::min<std::size_t>(8192, max_bytes) : max_bytes;

      // Binary scan (works on uncompressed regions + headers).
      auto fallback = scanRecoveryFileBinary(*resolved, "Hiber", "Hiber.binary",
                                             scan_limit, max_candidates_per_source_);
      binary_count += fallback.size();
      appendUniqueEvidence(results, fallback, dedup);

      // Additionally scan the first MB for EPROCESS + network pools.
      constexpr std::size_t kScanPrefix = 1 * 1024 * 1024;
      auto prefix_opt = EvidenceUtils::readFilePrefix(*resolved, kScanPrefix);
      if (prefix_opt.has_value() && !prefix_opt->empty()) {
        std::error_code ec;
        const std::string ts =
            EvidenceUtils::fileTimeToUtcString(fs::last_write_time(*resolved, ec));

        // EPROCESS
        const auto eprocs = scanForEprocess(*prefix_opt);
        for (const auto& ep : eprocs) {
          if (results.size() >= max_candidates_per_source_) break;
          RecoveryEvidence ev;
          ev.executable_path = ep.image_name;
          ev.source          = "Hiber";
          ev.recovered_from  = "Hiber.eprocess";
          ev.timestamp       = ts;
          ev.details         =
              buildEprocessDetails(ep.pool_offset, ep.pid, "binary_prefix");
          const std::string key =
              ev.executable_path + "|Hiber.eprocess|" +
              std::to_string(ep.pool_offset);
          if (dedup.insert(key).second) {
            results.push_back(std::move(ev));
            ++binary_count;
          }
        }

        // TCP/UDP endpoints
        const auto endpoints = scanForNetworkEndpoints(*prefix_opt);
        for (const auto& ep : endpoints) {
          if (results.size() >= max_candidates_per_source_) break;
          RecoveryEvidence ev;
          ev.executable_path = ep.local_addr;
          ev.source          = "Hiber";
          std::string protocol_token = to_lower(ep.protocol);
          trim(protocol_token);
          if (protocol_token.empty()) {
            protocol_token = "network";
          }
          ev.recovered_from  = "Hiber." + protocol_token + "_endpoint";
          ev.timestamp       = ts;
          ev.details         =
              buildEndpointDetails(ep, ep.pool_offset, "binary_prefix");
          const std::string key = ev.executable_path + "|" + ev.recovered_from;
          if (dedup.insert(key).second) {
            results.push_back(std::move(ev));
            ++binary_count;
          }
        }
      }
    }
  }

  logger->info("Recovery(Hiber): native={} binary={} total={}", native_count,
               binary_count, results.size());
  return results;
}

}  // namespace WindowsDiskAnalysis
