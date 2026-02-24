/// @file volume_type.hpp
/// @brief Типы логических томов Windows

#pragma once

#include <cstdint>

namespace PrefetchAnalysis {

/// @enum VolumeType
/// @brief Типы логических томов Windows (битовая маска)
enum class VolumeType : uint32_t {
  UNKNOWN = 0x0000,    ///< Неизвестный тип тома
  FIXED = 0x0001,      ///< Локальный несъемный диск (HDD/SSD)
  REMOVABLE = 0x0002,  ///< Съемный носитель (USB, CD/DVD)
  NETWORK = 0x0004,    ///< Сетевой диск (SMB, NFS)
  OPTICAL = 0x0008,    ///< Оптический привод
  RAMDISK = 0x0010,    ///< RAM-диск
  VIRTUAL = 0x0020,    ///< Виртуальный диск (VHD/VHDX)
  SYSTEM = 0x0040,     ///< Системный раздел
  CLOUD = 0x0080,      ///< Облачное хранилище
  ENCRYPTED = 0x0100,  ///< Шифрованный том
  TEMPORARY = 0x0200,  ///< Временное хранилище
};

}
