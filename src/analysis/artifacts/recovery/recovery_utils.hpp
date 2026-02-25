/// @file recovery_utils.hpp
/// @brief Общие утилиты для recovery-анализаторов (USN/VSS/Pagefile/Memory).

#pragma once

#include <cstddef>
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

