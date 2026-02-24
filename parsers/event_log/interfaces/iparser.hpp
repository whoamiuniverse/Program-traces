/// @file iparser.hpp
/// @brief Интерфейс парсера журналов событий Windows

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "../data_model/idata.hpp"

namespace EventLogAnalysis {

/// @brief Базовый интерфейс парсера журналов событий Windows
/// @interface IEventLogParser
/// @details Обеспечивает единый интерфейс для работы с различными форматами
/// журналов событий Windows. Реализации должны предоставлять методы для чтения
/// событий из файлов и их фильтрации по идентификаторам
class IEventLogParser {
 public:
  /// @brief Виртуальный деструктор по умолчанию
  virtual ~IEventLogParser() = default;

  /// @brief Разобрать все события из файла журнала
  /// @param[in] file_path Путь к файлу журнала событий
  /// @return Вектор уникальных указателей на разобранные события
  /// @note Реализация должна самостоятельно обрабатывать формат файла
  virtual std::vector<std::unique_ptr<IEventData>> parseEvents(
      const std::string& file_path) = 0;

  /// @brief Получить события определенного типа из файла журнала
  /// @param[in] file_path Путь к файлу журнала событий
  /// @param[in] event_id Идентификатор искомого типа событий
  /// @return Вектор уникальных указателей на отфильтрованные события
  /// @note Реализация должна обеспечить фильтрацию событий по event_id
  virtual std::vector<std::unique_ptr<IEventData>> getEventsByType(
      const std::string& file_path, uint32_t event_id) = 0;
};

}
