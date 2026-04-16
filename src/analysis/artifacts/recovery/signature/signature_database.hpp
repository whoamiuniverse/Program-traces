/// @file signature_database.hpp
/// @brief Static table of binary signatures for Windows forensic artifacts.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace WindowsDiskAnalysis {

/// @struct ArtifactSignature
/// @brief Descriptor of a binary signature for one Windows forensic artifact format.
struct ArtifactSignature {
  std::string_view artifact_type;  ///< Human-readable artifact type label.
  std::string_view recovered_from; ///< Recovery category label used in RecoveryEvidence.
  const uint8_t*   bytes;          ///< Pointer to the raw signature bytes.
  std::size_t      byte_count;     ///< Number of bytes in the signature.
  std::size_t      file_offset;    ///< Byte offset of the signature from the start of the artifact.
  std::size_t      min_size;       ///< Minimum plausible artifact size in bytes.
};

namespace SignatureDB {

// ---- Prefetch (format version in byte [7]) ----
// MAM\x17 = v23 (Vista/7), \x1A = v26 (Win8), \x1E = v30 (Win10), \x1F = v31 (Win11)
// Offset 4 holds the format version; bytes 0-3 are always 53 43 43 41 ("SCCA")
// The compressed wrapper (Win10+) starts with 4D 41 4D at offset 0.

inline constexpr std::array<uint8_t, 4> kSigPrefetchScca  = {0x53,0x43,0x43,0x41};
inline constexpr std::array<uint8_t, 3> kSigPrefetchMam   = {0x4D,0x41,0x4D};

// ---- EVTX file header (Windows Vista+ event log file) ----
// ElfFile\x00\x00
inline constexpr std::array<uint8_t, 8> kSigEvtx = {
    0x45,0x4C,0x46,0x49,0x4C,0x45,0x00,0x00};

// ---- EVTX chunk header (ElfChnk\x00) ----
// Each 65536-byte chunk within an EVTX file starts with this 8-byte magic.
// Useful for carving individual chunks from unallocated space.
inline constexpr std::array<uint8_t, 8> kSigEvtxChunk = {
    0x45,0x6C,0x66,0x43,0x68,0x6E,0x6B,0x00};

// ---- EVT (legacy Windows XP event log) ----
inline constexpr std::array<uint8_t, 4> kSigEvt  = {0x30,0x00,0x00,0x00};

// ---- LNK / Shell Link ----
// Header size = 0x4C, CLSID starts with 01 14 02 00
inline constexpr std::array<uint8_t, 8> kSigLnk  = {
    0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00};

// ---- Registry hive (regf) ----
inline constexpr std::array<uint8_t, 4> kSigRegf = {0x72,0x65,0x67,0x66};

// ---- Registry hive bin (hbin) ----
// Each 4096-byte hive-bin block inside a registry hive starts with "hbin".
// This allows recovery of individual hive-bin fragments from deleted hives.
inline constexpr std::array<uint8_t, 4> kSigHbin = {0x68,0x62,0x69,0x6E};

// ---- ESE / JET database (Amcache, SRUM, Windows Search) ----
// File format signature at offset 4
inline constexpr std::array<uint8_t, 4> kSigEse  = {0xEF,0xCD,0xAB,0x89};

// ---- SQLite (Windows Timeline / ActivitiesCache.db) ----
inline constexpr std::array<uint8_t, 6> kSigSqlite = {
    0x53,0x51,0x4C,0x69,0x74,0x65};

// ---- PE (EXE / DLL / SYS) ----
inline constexpr std::array<uint8_t, 2> kSigMz = {0x4D,0x5A};

// ---- OLE2 Compound File (MSI, legacy Office) ----
inline constexpr std::array<uint8_t, 8> kSigOle = {
    0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};

// ---- Task Scheduler Job file (1.0 binary format) ----
// The fixed-length section of a .job file starts with ProductVersion (WORD) and
// FileVersion (WORD). The magic discriminator is the Reserved1 WORD at offset 0x08
// which is always 0x0000, and ProductVersion is typically 0x0400 (Win NT 4.0).
// A stronger discriminator: the FIXED_LEN_DATA section is 0x44 (68) bytes;
// bytes 4-5 (FileVersion) is 0x0001 for Task Scheduler 1.0.
// We use the 4-byte sequence: product_ver=0x0400, file_ver=0x0001.
inline constexpr std::array<uint8_t, 4> kSigJobFile = {
    0x00,0x04,  // ProductVersion = 0x0400 LE
    0x01,0x00}; // FileVersion    = 0x0001 LE

/// @brief The complete static signature database.
/// Ordered from most-specific (longest, higher false-positive cost) to least.
inline constexpr std::array<ArtifactSignature, 12> kSignatures = {{
    {"EVTX",      "SigScan(evtx)",      kSigEvtx.data(),      kSigEvtx.size(),      0, 4096},
    {"EVTXChunk", "SigScan(evtx_chnk)", kSigEvtxChunk.data(), kSigEvtxChunk.size(), 0, 65536},
    {"LNK",       "SigScan(lnk)",       kSigLnk.data(),       kSigLnk.size(),       0,    76},
    {"OLE2/MSI",  "SigScan(ole)",       kSigOle.data(),       kSigOle.size(),       0, 4096},
    {"RegHive",   "SigScan(regf)",      kSigRegf.data(),      kSigRegf.size(),      0, 4096},
    {"HiveBin",   "SigScan(hbin)",      kSigHbin.data(),      kSigHbin.size(),      0, 4096},
    {"ESE/JET",   "SigScan(ese)",       kSigEse.data(),       kSigEse.size(),       4, 8192},
    {"SQLite",    "SigScan(sqlite)",    kSigSqlite.data(),    kSigSqlite.size(),    0, 1024},
    {"Prefetch",  "SigScan(pf)",        kSigPrefetchScca.data(), kSigPrefetchScca.size(), 0, 1024},
    {"PfCmpr",    "SigScan(pf_mam)",   kSigPrefetchMam.data(),  kSigPrefetchMam.size(),  0, 1024},
    {"JobFile",   "SigScan(job)",       kSigJobFile.data(),   kSigJobFile.size(),   0,   68},
    {"PE",        "SigScan(pe)",        kSigMz.data(),        kSigMz.size(),        0,  512},
}};

}  // namespace SignatureDB
}  // namespace WindowsDiskAnalysis
