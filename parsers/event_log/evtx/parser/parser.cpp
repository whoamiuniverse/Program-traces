#include "parser.hpp"

#include <regex>
#include <vector>

#include "../../../../core/exceptions/parsing_exception.hpp"
#include "../../../../utils/logging/logger.hpp"

namespace EventLogAnalysis {

using namespace std::string_literals;

EvtxParser::EvtxParser() {
  const auto logger = GlobalLogger::get();
  logger->debug("Инициализация EvtxParser");

  libevtx_error_t* error = nullptr;
  if (libevtx_file_initialize(&evtx_file_, &error) != 1) {
    std::string error_msg = "Ошибка инициализации libevtx";
    if (error) {
      char error_buffer[256];
      libevtx_error_sprint(error, error_buffer, sizeof(error_buffer));
      libevtx_error_free(&error);
    }
    throw InitLibError("libevtx");
  }
}

EvtxParser::~EvtxParser() {
  const auto logger = GlobalLogger::get();
  CloseLogFile();
  if (evtx_file_) {
    libevtx_file_free(&evtx_file_, nullptr);
  }
}

void EvtxParser::OpenLogFile(const std::string& file_path) {
  const auto logger = GlobalLogger::get();

  if (file_opened_) {
    logger->debug("Закрытие предыдущего открытого EVTX файла");
    CloseLogFile();
  }

  libevtx_error_t* error = nullptr;
  const int access_flags = libevtx_get_access_flags_read();

  if (libevtx_file_open(evtx_file_, file_path.c_str(), access_flags, &error) !=
      1) {
    std::string error_msg = "Не удалось открыть файл: "s + file_path;
    if (error) {
      char error_buffer[256];
      libevtx_error_sprint(error, error_buffer, sizeof(error_buffer));
      libevtx_error_free(&error);
    }
    throw FileOpenException(file_path);
  }
  file_opened_ = true;
}

void EvtxParser::CloseLogFile() {
  const auto logger = GlobalLogger::get();

  if (file_opened_ && evtx_file_) {
    logger->debug("Закрытие EVTX файла");
    libevtx_file_close(evtx_file_, nullptr);
    file_opened_ = false;
  }
}

std::unique_ptr<EventData> EvtxParser::ParseRecord(libevtx_record_t* record) {
  const auto logger = GlobalLogger::get();
  auto event_data = std::make_unique<EventData>();
  libevtx_error_t* error = nullptr;

  // Получение идентификатора события
  uint32_t event_id = 0;
  if (libevtx_record_get_event_identifier(record, &event_id, &error) == 1) {
    event_data->setEventID(event_id);
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение времени записи
  uint64_t timestamp = 0;
  if (libevtx_record_get_written_time(record, &timestamp, &error) == 1) {
    event_data->setTimestamp(timestamp);
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение уровня события
  uint8_t level = 0;
  if (libevtx_record_get_event_level(record, &level, &error) == 1) {
    event_data->setLevel(static_cast<EventLevel>(level));
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение провайдера (UTF-8)
  size_t provider_size = 0;
  if (libevtx_record_get_utf8_provider_identifier_size(record, &provider_size,
                                                       &error) == 1) {
    if (provider_size > 0) {
      std::vector<char> buffer(provider_size);
      if (libevtx_record_get_utf8_provider_identifier(
              record, reinterpret_cast<uint8_t*>(buffer.data()), provider_size,
              &error) == 1) {
        event_data->setProvider(buffer.data());
      } else if (error) {
        libevtx_error_free(&error);
      }
    }
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение имени компьютера (UTF-8)
  size_t computer_size = 0;
  if (libevtx_record_get_utf8_computer_name_size(record, &computer_size,
                                                 &error) == 1) {
    if (computer_size > 0) {
      std::vector<char> buffer(computer_size);
      if (libevtx_record_get_utf8_computer_name(
              record, reinterpret_cast<uint8_t*>(buffer.data()), computer_size,
              &error) == 1) {
        event_data->setComputer(buffer.data());
      } else if (error) {
        libevtx_error_free(&error);
      }
    }
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение имени канала (UTF-8)
  size_t channel_size = 0;
  if (libevtx_record_get_utf8_channel_name_size(record, &channel_size,
                                                &error) == 1) {
    if (channel_size > 0) {
      std::vector<char> buffer(channel_size);
      if (libevtx_record_get_utf8_channel_name(
              record, reinterpret_cast<uint8_t*>(buffer.data()), channel_size,
              &error) == 1) {
        event_data->setChannel(buffer.data());
      } else if (error) {
        libevtx_error_free(&error);
      }
    }
  } else if (error) {
    libevtx_error_free(&error);
  }

  // Получение XML представления
  size_t xml_size = 0;
  if (libevtx_record_get_utf8_xml_string_size(record, &xml_size, &error) == 1) {
    if (xml_size > 0) {
      std::vector<char> buffer(xml_size);
      if (libevtx_record_get_utf8_xml_string(
              record, reinterpret_cast<uint8_t*>(buffer.data()), xml_size,
              &error) == 1) {
        std::string xml_string = buffer.data();
        event_data->setXml(xml_string);
        ExtractEventDataFromXml(*event_data, xml_string);
      } else if (error) {
        libevtx_error_free(&error);
      }
    }
  } else if (error) {
    libevtx_error_free(&error);
  }

  return event_data;
}

void EvtxParser::ExtractEventDataFromXml(EventData& event_data,
                                         const std::string& xml) {
  const auto logger = GlobalLogger::get();

  try {
    // Извлечение данных из элементов <EventData>
    std::regex data_regex(R"(<Data\s+Name="([^"]+)\"[^>]*>([^<]*)</Data>)");
    auto data_begin = std::sregex_iterator(xml.begin(), xml.end(), data_regex);
    auto data_end = std::sregex_iterator();

    for (auto i = data_begin; i != data_end; ++i) {
      const std::smatch& match = *i;
      if (match.size() == 3) {
        std::string name = match[1].str();
        std::string value = match[2].str();

        // Удаление XML-экранирования
        size_t pos;
        while ((pos = value.find("&amp;")) != std::string::npos)
          value.replace(pos, 5, "&");
        while ((pos = value.find("&lt;")) != std::string::npos)
          value.replace(pos, 4, "<");
        while ((pos = value.find("&gt;")) != std::string::npos)
          value.replace(pos, 4, ">");
        while ((pos = value.find("&quot;")) != std::string::npos)
          value.replace(pos, 6, "\"");
        while ((pos = value.find("&apos;")) != std::string::npos)
          value.replace(pos, 6, "'");

        event_data.addData(name, value);

        // Использование CommandLine как описания для событий выполнения
        // процессов
        if (name == "CommandLine") {
          event_data.setDescription(value);
        }
      }
    }
  } catch (const std::regex_error& e) {
    logger->debug("Ошибка регулярного выражения при разборе XML: {}", e.what());
  }

  // Извлечение описания, если не установлено из CommandLine
  if (event_data.getDescription().empty()) {
    try {
      std::regex desc_regex(R"(<Description>([^<]+)</Description>)");
      std::smatch match;
      if (std::regex_search(xml, match, desc_regex) && match.size() > 1) {
        event_data.setDescription(match[1].str());
      }
    } catch (const std::regex_error& e) {
      logger->debug("Ошибка регулярного выражения при разборе Description: {}",
                   e.what());
    }
  }
}

std::vector<std::unique_ptr<IEventData>> EvtxParser::parseEvents(
    const std::string& file_path) {
  const auto logger = GlobalLogger::get();

  try {
    OpenLogFile(file_path);

    logger->debug("Начало обработки EVTX файла: \"{}\"", file_path);

    libevtx_error_t* error = nullptr;
    int record_count = 0;
    std::vector<std::unique_ptr<IEventData>> events;

    // Получение количества записей
    if (libevtx_file_get_number_of_records(evtx_file_, &record_count, &error) !=
        1) {
      std::string error_msg = "Не удалось получить количество записей";
      if (error) {
        char error_buffer[256];
        libevtx_error_sprint(error, error_buffer, sizeof(error_buffer));
        error_msg += ": "s + error_buffer;
        libevtx_error_free(&error);
      }
      throw DataReadException(error_msg);
    }

    logger->debug("Найдено \"{}\" записей в EVTX файле", record_count);

    // Получение всех записей
    for (int i = 0; i < record_count; i++) {
      libevtx_record_t* record = nullptr;
      if (libevtx_file_get_record_by_index(evtx_file_, i, &record, &error) ==
          1) {
        events.push_back(ParseRecord(record));
        libevtx_record_free(&record, nullptr);
      } else if (error) {
        libevtx_error_free(&error);
      }
    }

    logger->debug("Файл успешно обработан. Успешно разобрано \"{}\" событие",
                 events.size());
    return events;
  } catch (...) {
    CloseLogFile();
    throw;
  }
}

std::vector<std::unique_ptr<IEventData>> EvtxParser::getEventsByType(
    const std::string& file_path, uint32_t event_id) {
  const auto logger = GlobalLogger::get();
  logger->debug("Фильтрация событий по ID \"{}\" из EVTX файла: \"{}\"", event_id,
               file_path);

  try {
    OpenLogFile(file_path);

    libevtx_error_t* error = nullptr;
    int record_count = 0;
    std::vector<std::unique_ptr<IEventData>> filtered_events;

    // Получение количества записей
    if (libevtx_file_get_number_of_records(evtx_file_, &record_count, &error) !=
        1) {
      std::string error_msg = "Не удалось получить количество записей";
      if (error) {
        char error_buffer[256];
        libevtx_error_sprint(error, error_buffer, sizeof(error_buffer));
        error_msg += ": "s + error_buffer;
        libevtx_error_free(&error);
      }
      throw DataReadException(error_msg);
    }

    logger->debug("Найдено \"{}\" записей в EVTX файле", record_count);

    // Фильтрация записей по ID события
    for (int i = 0; i < record_count; i++) {
      libevtx_record_t* record = nullptr;
      if (libevtx_file_get_record_by_index(evtx_file_, i, &record, &error) ==
          1) {
        uint32_t current_id = 0;
        if (libevtx_record_get_event_identifier(record, &current_id, nullptr) ==
                1 &&
            current_id == event_id) {
          filtered_events.push_back(ParseRecord(record));
        }
        libevtx_record_free(&record, nullptr);
      } else if (error) {
        libevtx_error_free(&error);
      }
    }

    logger->debug("Найдено \"{}\" событий с ID \"{}\"", filtered_events.size(),
                 event_id);
    return filtered_events;
  } catch (...) {
    CloseLogFile();
    throw;
  }
}

}
