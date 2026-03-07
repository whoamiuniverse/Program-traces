/// @file recovery_utils.hpp
/// @brief Общие утилиты для recovery-анализаторов (USN/VSS/Pagefile/Memory).

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"

namespace WindowsDiskAnalysis::RecoveryUtils {

/// @brief Ищет путь в ФС без учета регистра каждого компонента.
/// @param input_path Исходный путь для проверки.
/// @return Разрешённый путь при успехе, иначе `std::nullopt`.
[[nodiscard]] std::optional<std::filesystem::path> findPathCaseInsensitive(
    const std::filesystem::path& input_path);

/// @brief Переводит лимит в мегабайтах в байты.
/// @param megabytes Лимит в MB.
/// @return Лимит в байтах (минимум 1 MB).
[[nodiscard]] std::size_t toByteLimit(std::size_t megabytes);

/// @brief Выполняет бинарный fallback-скан файла на пути исполняемых файлов.
/// @param file_path Путь к файлу источника.
/// @param source Логический источник (`USN`, `VSS`, `Pagefile` и т.д.).
/// @param recovered_from Маркер вида восстановления (`USN(binary)` и т.д.).
/// @param max_bytes Максимум читаемых байтов из начала файла.
/// @param max_candidates Ограничение числа извлеченных кандидатов.
/// @return Набор `RecoveryEvidence`, полученных из бинарного скана.
[[nodiscard]] std::vector<RecoveryEvidence> scanRecoveryFileBinary(
    const std::filesystem::path& file_path, const std::string& source,
    const std::string& recovered_from, std::size_t max_bytes,
    std::size_t max_candidates);

/// @brief Выполняет сигнатурный/строковый recovery-скан уже загруженного буфера.
/// @param buffer Содержимое сканируемого блока.
/// @param source Логический источник (`USN`, `VSS`, `Memory`, ...).
/// @param recovered_from Маркер вида восстановления (`Hiber(native)` и т.д.).
/// @param container_label Метка контейнера (например имя файла).
/// @param timestamp Временная метка источника.
/// @param max_candidates Ограничение числа возвращаемых кандидатов.
/// @param base_offset Смещение буфера относительно начала контейнера.
/// @param chunk_source Источник чанка (`file_head`, `mft_record`, ...).
/// @param container_size Полный размер анализируемого контейнера для корректной
/// маркировки чанка как `head`/`middle`/`tail`. Если `0`, используется размер
/// текущего буфера.
/// @return Набор `RecoveryEvidence`, извлеченный из буфера.
[[nodiscard]] std::vector<RecoveryEvidence> scanRecoveryBufferBinary(
    const std::vector<uint8_t>& buffer, const std::string& source,
    const std::string& recovered_from, const std::string& container_label,
    const std::string& timestamp, std::size_t max_candidates,
    std::uint64_t base_offset = 0,
    const std::string& chunk_source = "buffer",
    std::size_t container_size = 0);

/// @brief Собирает ключ дедупликации для записи recovery evidence.
/// @param evidence Запись evidence.
/// @return Нормализованный строковый ключ.
[[nodiscard]] std::string buildEvidenceDedupKey(
    const RecoveryEvidence& evidence);

/// @brief Добавляет записи в целевой вектор без дублей.
/// @param target Целевой вектор результатов.
/// @param source Источник записей (будет перемещен).
/// @param dedup_keys Набор ключей дедупликации.
void appendUniqueEvidence(std::vector<RecoveryEvidence>& target,
                          std::vector<RecoveryEvidence>& source,
                          std::unordered_set<std::string>& dedup_keys);

}  // namespace WindowsDiskAnalysis::RecoveryUtils
