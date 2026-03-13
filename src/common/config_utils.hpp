/// @file config_utils.hpp
/// @brief Общие helper-функции для чтения конфигурации с fallback-логикой.

#pragma once

#include <string>
#include <string_view>

#include "infra/config/config.hpp"

namespace WindowsDiskAnalysis::ConfigUtils {

/// @brief Возвращает значение для версии ОС с fallback на общую секцию.
/// @param config Загруженный INI-конфиг.
/// @param version Секция версии ОС (`Windows10`, `Windows7` и т.д.).
/// @param key Искомый ключ.
/// @param defaults_section Секция fallback-значений.
/// @return Найденное значение либо пустая строка.
inline std::string getWithVersionFallback(
    const Config& config, const std::string& version, const std::string& key,
    const std::string_view defaults_section = "VersionDefaults") {
  if (config.hasKey(version, key)) {
    return config.getString(version, key, "");
  }

  const std::string defaults(defaults_section);
  if (config.hasKey(defaults, key)) {
    return config.getString(defaults, key, "");
  }

  return {};
}

/// @brief Возвращает значение из секции с fallback на ключ `Default`.
/// @param config Загруженный INI-конфиг.
/// @param section Секция конфигурации.
/// @param key Основной ключ.
/// @param default_key Ключ fallback внутри той же секции.
/// @return Найденное значение либо пустая строка.
inline std::string getWithSectionDefault(
    const Config& config, const std::string& section, const std::string& key,
    const std::string_view default_key = "Default") {
  if (config.hasKey(section, key)) {
    return config.getString(section, key, "");
  }

  const std::string fallback(default_key);
  if (config.hasKey(section, fallback)) {
    return config.getString(section, fallback, "");
  }

  return {};
}

/// @brief Возвращает значение из секции с несколькими уровнями fallback.
/// @param config Загруженный INI-конфиг.
/// @param section Основная секция.
/// @param key Основной ключ.
/// @param fallback_section Секция последнего fallback.
/// @param fallback_key Ключ последнего fallback.
/// @param default_key Ключ `Default` внутри основной секции.
/// @return Найденное значение либо пустая строка.
inline std::string getWithSectionDefaultAndFallback(
    const Config& config, const std::string& section, const std::string& key,
    const std::string& fallback_section, const std::string& fallback_key,
    const std::string_view default_key = "Default") {
  std::string value = getWithSectionDefault(config, section, key, default_key);
  if (!value.empty()) {
    return value;
  }

  if (config.hasKey(fallback_section, fallback_key)) {
    return config.getString(fallback_section, fallback_key, "");
  }

  return {};
}

}  // namespace WindowsDiskAnalysis::ConfigUtils
