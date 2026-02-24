/// @file parser.hpp
/// @brief Парсер событий из файлов формата EVTX (Windows Event Log) с
/// использованием библиотеки libevtx

#pragma once

#include <libevtx.h>

#include <memory>
#include <string>
#include <vector>

#include "../../../../core/exceptions/parsing_exception.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../data_model/data.hpp"
#include "../../data_model/idata.hpp"
#include "../../interfaces/iparser.hpp"

namespace EventLogAnalysis {

/// @class EvtxParser
/// @brief Парсер событий из файлов формата EVTX (Windows Event Log) с
/// использованием библиотеки libevtx
/// @details Класс реализует интерфейс IEventLogParser для работы с журналами
/// событий Windows в формате EVTX
class EvtxParser final : public IEventLogParser {
 public:
  /// @brief Конструктор по умолчанию
  /// @throws InitLibError Если произошла ошибка инициализации библиотеки
  /// libevtx
  EvtxParser();

  /// @brief Деструктор (автоматически закрывает открытый файл при уничтожении
  /// объекта)
  ~EvtxParser() override;

  /// Запрещенный конструктор копирования
  EvtxParser(const EvtxParser&) = delete;

  /// Запрещенный оператор присваивания
  EvtxParser& operator=(const EvtxParser&) = delete;

  /// @copydoc IEventLogParser::parseEvents
  /// @throws FileOpenException Если файл не существует или недоступен для
  /// чтения
  /// @throws DataReadException Если произошла ошибка чтения данных из файла
  std::vector<std::unique_ptr<IEventData>> parseEvents(
      const std::string& file_path) override;

  /// @copydoc EvtxParser::getEventsByType
  /// @throws FileOpenException Если файл не существует или недоступен для
  /// чтения
  /// @throws DataReadException Если произошла ошибка чтения данных из файла
  std::vector<std::unique_ptr<IEventData>> getEventsByType(
      const std::string& file_path, uint32_t event_id) override;

 private:
  /// @brief Конвертирует запись libevtx в унифицированный формат EventData
  /// @param[in] record Указатель на структуру записи libevtx_record_t
  /// @return Уникальный указатель на объект EventData с распарсенными данными
  static std::unique_ptr<EventData> ParseRecord(libevtx_record_t* record);

  /// @brief Извлекает дополнительные данные события из XML-представления
  /// @param[out] event_data Ссылка на объект EventData для заполнения
  /// дополнительными данными
  /// @param[in] xml XML-строка, содержащая данные события
  static void ExtractEventDataFromXml(EventData& event_data,
                                      const std::string& xml);

  /// @brief Открывает EVTX-файл для последующего парсинга
  /// @param[in] file_path Путь к EVTX-файлу
  /// @throws FileOpenException Если файл не может быть открыт или имеет
  /// неверный формат
  void OpenLogFile(const std::string& file_path);

  /// @brief Закрывает текущий открытый EVTX-файл и освобождает ресурсы
  void CloseLogFile();

  libevtx_file_t* evtx_file_ =
      nullptr;                ///< Указатель на файловый объект libevtx
  bool file_opened_ = false;  ///< Флаг состояния файла (true - файл открыт)
};

}
