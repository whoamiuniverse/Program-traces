/// @file windows_disk_analyzer_helpers.hpp
/// @brief Вспомогательные типы и функции оркестратора анализа Windows-диска.

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "errors/disk_analyzer_exception.hpp"
#include "infra/config/config.hpp"
#include "parsers/registry/data_model/idata.hpp"
#include "parsers/registry/parser/iparser.hpp"

namespace WindowsDiskAnalysis::Orchestrator::Detail {

/// @struct MountedRootInfo
/// @brief Описание точки монтирования и соответствующего устройства.
struct MountedRootInfo {
  std::string device_path;  ///< Путь к устройству (`/dev/diskXsY`).
  std::string mount_root;   ///< Точка монтирования (`/Volumes/...`).
};

/// @struct WindowsRootSummary
/// @brief Краткая информация о Windows-системе на найденном томе.
struct WindowsRootSummary {
  std::string product_name;         ///< ProductName из SOFTWARE hive.
  std::string installation_type;    ///< InstallationType из SOFTWARE hive.
  std::string system_product_type;  ///< ProductType из SYSTEM hive.
  std::string build;                ///< CurrentBuild/CurrentBuildNumber.
  std::string mapped_name;          ///< Нормализованное имя по build mapping.
};

/// @struct AutoSelectCandidate
/// @brief Кандидат для авто-выбора Windows-тома.
struct AutoSelectCandidate {
  MountedRootInfo mount;  ///< Информация о точке монтирования.
  std::string os_label;   ///< Отображаемая подпись версии Windows.
};

/// @class ScopedDebugLevelOverride
/// @brief Временно поднимает уровень логирования до `info`, если debug выключен.
class ScopedDebugLevelOverride {
 public:
  /// @brief Создаёт guard переключения уровня логирования.
  /// @param debug_enabled Включен ли debug для текущего этапа.
  explicit ScopedDebugLevelOverride(bool debug_enabled);

  /// @brief Восстанавливает исходный уровень логирования.
  ~ScopedDebugLevelOverride();

 private:
  std::shared_ptr<spdlog::logger> logger_;
  spdlog::level::level_enum previous_level_ = spdlog::level::info;
  bool active_ = false;
};

/// @brief Добавляет завершающий `/` к пути, если отсутствует.
[[nodiscard]] std::string ensureTrailingSlash(std::string path);

/// @brief Приводит ASCII-строку к нижнему регистру.
[[nodiscard]] std::string toLowerAscii(std::string text);

/// @brief Добавляет токен в вектор без дубликатов (case-insensitive).
void appendUniqueToken(std::vector<std::string>& target, std::string token);

/// @brief Добавляет tamper-флаг к процессу без дубликатов.
void appendTamperFlag(ProcessInfo& info, const std::string& flag);

/// @brief Добавляет источник evidence к процессу без дубликатов.
void appendEvidenceSource(ProcessInfo& info, const std::string& source);

/// @brief Добавляет timeline-артефакт к процессу без дубликатов.
void appendTimelineArtifact(ProcessInfo& info, const std::string& artifact);

/// @brief Добавляет source в `recovered_from` процесса без дубликатов.
void appendRecoveredFrom(ProcessInfo& info, const std::string& source);

/// @brief Проверяет включён ли режим auto для `DiskRoot`.
[[nodiscard]] bool isAutoDiskRootValue(std::string value);

/// @brief Проверяет, относится ли код ошибки к проблемам прав доступа.
[[nodiscard]] bool isAccessDeniedError(const std::error_code& ec);

/// @brief Проверяет текст ошибки на признаки отказа в доступе.
[[nodiscard]] bool containsAccessDenied(std::string_view message);

/// @brief Форматирует `std::error_code` в читаемое сообщение.
[[nodiscard]] std::string formatFilesystemError(const std::error_code& ec);

/// @brief Формирует короткую метку устройства (`diskXsY`).
[[nodiscard]] std::string formatDeviceLabel(const std::string& device_path);

/// @brief Проверяет, что значение похоже на server-вариант Windows.
[[nodiscard]] bool isServerLikeValue(const std::string& value);

/// @brief Нормализует разделители пути к `/`.
[[nodiscard]] std::string normalizePathSeparators(std::string path);

/// @brief Строит путь к SYSTEM hive на основе пути к SOFTWARE hive.
[[nodiscard]] std::string deriveSystemHivePathFromSoftwarePath(
    std::string software_hive_path);

/// @brief Извлекает индекс ControlSet из registry value.
[[nodiscard]] std::optional<uint32_t> parseControlSetIndex(
    const std::unique_ptr<RegistryAnalysis::IRegistryData>& value);

/// @brief Пытается прочитать `ProductType` из SYSTEM hive.
[[nodiscard]] std::string tryReadSystemProductType(
    RegistryAnalysis::IRegistryParser& parser,
    const std::string& system_hive_path);

/// @brief Классифицирует client/server по `ProductType`.
[[nodiscard]] std::optional<bool> classifyServerByProductType(
    const std::string& system_product_type);

/// @brief Находит маппинг имени Windows по порогу build-номера.
[[nodiscard]] std::optional<std::string> findMappedNameByBuildThreshold(
    const Config& config, const std::string& section, uint32_t build_number);

/// @brief Выбирает итоговое имя Windows с учётом build-map и server/client.
[[nodiscard]] std::string resolveMappedWindowsName(
    const Config& config, const WindowsRootSummary& summary);

/// @brief Возвращает точку монтирования для устройства.
[[nodiscard]] std::string resolveMountedPath(const std::string& device_path);

/// @brief Возвращает список доступных смонтированных корней.
[[nodiscard]] std::vector<MountedRootInfo> listMountedRoots();

/// @brief Нормализует аргумент `disk_root` к точке монтирования.
/// @throws DiskNotMountedException Если устройство не смонтировано.
/// @throws InvalidDiskRootException Если путь невалиден.
[[nodiscard]] std::string normalizeDiskRoot(std::string disk_root);

/// @brief Парсит список значений из INI (`a,b,c`).
[[nodiscard]] std::vector<std::string> parseListSetting(std::string value);

/// @brief Читает ключ из секции с fallback на `Default`.
[[nodiscard]] std::string getConfigValueWithSectionDefault(
    const Config& config, const std::string& section, const std::string& key);

/// @brief Собирает уникальные пути SOFTWARE hive из конфигурации.
[[nodiscard]] std::vector<std::pair<std::string, std::string>>
collectRegistryHiveCandidates(const Config& config);

/// @brief Находит путь в ФС без учёта регистра компонентов.
[[nodiscard]] std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path,
    std::string* error_reason = nullptr);

/// @brief Пытается извлечь summary Windows из SOFTWARE/SYSTEM hive на томе.
[[nodiscard]] std::optional<WindowsRootSummary> detectWindowsRootSummary(
    const Config& config, const std::string& mount_root,
    std::string* error_reason = nullptr);

/// @brief Формирует человеко-читаемую подпись Windows.
[[nodiscard]] std::string formatWindowsLabel(const WindowsRootSummary& summary);

/// @brief Мержит recovery evidence в общую таблицу процессов.
void mergeRecoveryEvidenceToProcessData(
    const std::vector<RecoveryEvidence>& recovery_entries,
    std::map<std::string, ProcessInfo>& process_data);

/// @brief Проверяет наличие интерактивного stdin.
[[nodiscard]] bool hasInteractiveStdin();

}  // namespace WindowsDiskAnalysis::Orchestrator::Detail
