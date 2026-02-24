/// @file parser.hpp
/// @brief Парсер для работы с EVT-файлами (журналами событий Windows) с
/// использованием библиотеки libevt

#pragma once

#include <libevt.h>

#include <memory>
#include <string>
#include <vector>

#include "../../../../core/exceptions/parsing_exception.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../data_model/data.hpp"
#include "../../data_model/idata.hpp"
#include "../../interfaces/iparser.hpp"

namespace EventLogAnalysis {

/// @class EvtParser
/// @brief Парсер для работы с EVT-файлами (журналами событий Windows) с
/// использованием библиотеки libevt
/// @details Класс предоставляет функциональность для чтения и обработки событий
/// из EVT-файлов
class EvtParser final : public IEventLogParser {
 public:
  /// @brief Конструктор по умолчанию
  EvtParser();

  /// @brief Деструктор по умолчанию
  ~EvtParser() override;

  /// @brief Запрещенный конструктор копирования
  EvtParser(const EvtParser&) = delete;

  /// @brief Запрещенный оператор присваивания
  EvtParser& operator=(const EvtParser&) = delete;

  /// @copydoc IEventLogParser::parseEvents
  /// @throws FileOpenException Если не удалось открыть файл
  /// @throws DataReadException Если произошла ошибка при чтении данных
  std::vector<std::unique_ptr<IEventData>> parseEvents(
      const std::string& file_path) override;

  /// @copydoc EvtParser::getEventsByType
  /// @throws FileOpenException Если не удалось открыть файл
  /// @throws DataReadException Если произошла ошибка при чтении данных
  std::vector<std::unique_ptr<IEventData>> getEventsByType(
      const std::string& file_path, uint32_t event_id) override;

 private:
  /// @brief Парсит отдельную запись события из libevt в унифицированный формат
  /// @param[in] record Указатель на запись события из libevt
  /// @return Уникальный указатель на объект EventData
  static std::unique_ptr<EventData> ParseRecord(libevt_record_t* record);

  /// @brief Открывает EVT-файл для парсинга
  /// @param[in] file_path Путь к EVT-файлу
  /// @throws FileOpenException Если не удалось открыть файл
  void OpenLogFile(const std::string& file_path);

  /// @brief Закрывает текущий открытый EVT-файл
  void CloseLogFile();

  /// @brief Конвертирует тип события EVT в унифицированный уровень важности
  /// @param[in] event_type Тип события из EVT-файла
  /// @return Уровень важности события в унифицированном формате
  static EventLevel ConvertEventTypeToLevel(uint16_t event_type);

  libevt_file_t* evt_file_ = nullptr;  ///< Указатель на файловый объект libevt
  bool file_opened_ =
      false;  ///< Флаг, указывающий открыт ли файл в данный момент
};

}
