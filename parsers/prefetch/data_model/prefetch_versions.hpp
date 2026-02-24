/// @file prefetch_versions.hpp
/// @brief Перечисление версий формата Prefetch-файлов Windows

#pragma once

#include <cstdint>

namespace PrefetchAnalysis {

/// @brief Перечисление версий формата Prefetch-файлов Windows
/// @details Каждое значение соответствует уникальному номеру версии в заголовке
/// файла. Подробности можно найти в документации Microsoft и исследованиях
/// формата Prefetch
/// @note Основные версии формата:
///    - 10: Windows XP (RTM, SP1)
///    - 11: Windows XP Embedded
///    - 17: Windows XP SP2+, Server 2003
///    - 23: Windows Vista, 7, Server 2008/R2
///    - 26: Windows 8-8.1, Server 2012/R2, Windows 10 TH1-TH2
///    - 30: Windows 10 RS1+ (1607+), Windows 11, Server 2016+
enum class PrefetchFormatVersion : uint8_t {
  WIN_XP_RTM = 10,       ///< Windows XP RTM (версия 10)
  WIN_XP_EMBEDDED = 11,  ///< Windows XP Embedded (версия 11)
  WIN_XP_SP2 = 17,       ///< Windows XP SP2+ / Server 2003 (версия 17)
  WIN_VISTA_7 = 23,      ///< Windows Vista/7/Server 2008/R2 (версия 23)
  WIN8_10_PRE_RS1 =
      26,  ///< Windows 8-8.1/Server 2012/R2/Win10 TH1-TH2 (версия 26)
  WIN10_RS1_PLUS =
      30,      ///< Windows 10 RS1+ (1607+)/Win11/Server 2016+ (версия 30)
  UNKNOWN = 0  ///< Неизвестная/неподдерживаемая версия
};

/// @brief Преобразует числовую версию в enum PrefetchFormatVersion
/// @param[in] version Числовая версия из заголовка файла
/// @return Соответствующее значение PrefetchFormatVersion
[[nodiscard]] static PrefetchFormatVersion toVersionEnum(
    const uint8_t version) {
  switch (version) {
    case 10:
      return PrefetchFormatVersion::WIN_XP_RTM;
    case 11:
      return PrefetchFormatVersion::WIN_XP_EMBEDDED;
    case 17:
      return PrefetchFormatVersion::WIN_XP_SP2;
    case 23:
      return PrefetchFormatVersion::WIN_VISTA_7;
    case 26:
      return PrefetchFormatVersion::WIN8_10_PRE_RS1;
    case 30:
      return PrefetchFormatVersion::WIN10_RS1_PLUS;
    default:
      return PrefetchFormatVersion::UNKNOWN;
  }
}

}
