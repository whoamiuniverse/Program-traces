#include "parser.hpp"

#include <sstream>
#include <vector>

#include "../../../../core/exceptions/parsing_exception.hpp"
#include "../../../../utils/logging/logger.hpp"

namespace EventLogAnalysis {

using namespace std::string_literals;

// Константы для преобразования времени
constexpr uint64_t EPOCH_DIFFERENCE =
    116444736000000000ULL;  // Разница между 1601 и 1970 годом в 100-нс
                            // интервалах

EvtParser::EvtParser() {
  const auto logger = GlobalLogger::get();
  logger->debug("Инициализация EvtParser");

  libevt_error_t* error = nullptr;
  if (libevt_file_initialize(&evt_file_, &error) != 1) {
    std::string error_msg = "Ошибка инициализации libevt";
    if (error) {
      char error_buffer[256];
      libevt_error_sprint(error, error_buffer, sizeof(error_buffer));
      error_msg += ": "s + error_buffer;
      libevt_error_free(&error);
    }
    logger->error(error_msg);
    throw InitLibError("libevt");
  }
}

EvtParser::~EvtParser() {
  const auto logger = GlobalLogger::get();
  CloseLogFile();
  if (evt_file_) {
    libevt_file_free(&evt_file_, nullptr);
  }
}

void EvtParser::OpenLogFile(const std::string& file_path) {
  const auto logger = GlobalLogger::get();

  if (file_opened_) {
    logger->debug("Закрытие предыдущего открытого EVT файла");
    CloseLogFile();
  }

  libevt_error_t* error = nullptr;
  int access_flags = libevt_get_access_flags_read();

  logger->debug("Открытие EVT файла: \"{}\"", file_path);
  if (libevt_file_open(evt_file_, file_path.c_str(), access_flags, &error) !=
      1) {
    std::string error_msg = "Не удалось открыть файл: "s + file_path;
    if (error) {
      char error_buffer[256];
      libevt_error_sprint(error, error_buffer, sizeof(error_buffer));
      error_msg += ": "s + error_buffer;
      libevt_error_free(&error);
    }
    logger->error(error_msg);
    throw FileOpenException(file_path);
  }
  file_opened_ = true;
}

void EvtParser::CloseLogFile() {
  const auto logger = GlobalLogger::get();

  if (file_opened_ && evt_file_) {
    logger->debug("Закрытие EVT файла");
    libevt_file_close(evt_file_, nullptr);
    file_opened_ = false;
  }
}

EventLevel EvtParser::ConvertEventTypeToLevel(uint16_t event_type) {
  switch (event_type) {
    case LIBEVT_EVENT_TYPE_ERROR:
      return EventLevel::ERROR;
    case LIBEVT_EVENT_TYPE_WARNING:
      return EventLevel::WARNING;
    case LIBEVT_EVENT_TYPE_INFORMATION:
    case LIBEVT_EVENT_TYPE_AUDIT_SUCCESS:
    case LIBEVT_EVENT_TYPE_AUDIT_FAILURE:
      return EventLevel::INFO;
    default:
      return EventLevel::LOG_ALWAYS;
  }
}

std::unique_ptr<EventData> EvtParser::ParseRecord(libevt_record_t* record) {
  const auto logger = GlobalLogger::get();
  auto event_data = std::make_unique<EventData>();
  libevt_error_t* error = nullptr;

  // Получение идентификатора события
  uint32_t event_id = 0;
  if (libevt_record_get_event_identifier(record, &event_id, &error) == 1) {
    event_data->setEventID(event_id);
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение времени записи (в секундах с 1970 года)
  uint32_t written_time = 0;
  if (libevt_record_get_written_time(record, &written_time, &error) == 1) {
    // Конвертация в формат FILETIME (100-нс интервалы с 1601 года)
    uint64_t filetime =
        (static_cast<uint64_t>(written_time) * 10000000ULL) + EPOCH_DIFFERENCE;
    event_data->setTimestamp(filetime);
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение типа события и конвертация в уровень
  uint16_t event_type = 0;
  if (libevt_record_get_event_type(record, &event_type, &error) == 1) {
    event_data->setLevel(ConvertEventTypeToLevel(event_type));
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение источника (provider)
  size_t source_size = 0;
  if (libevt_record_get_utf8_source_name_size(record, &source_size, &error) ==
          1 &&
      source_size > 0) {
    std::vector<char> buffer(source_size);
    if (libevt_record_get_utf8_source_name(
            record, reinterpret_cast<uint8_t*>(buffer.data()), source_size,
            &error) == 1) {
      event_data->setProvider(buffer.data());
    } else if (error) {
      libevt_error_free(&error);
    }
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение имени компьютера
  size_t computer_size = 0;
  if (libevt_record_get_utf8_computer_name_size(record, &computer_size,
                                                &error) == 1 &&
      computer_size > 0) {
    std::vector<char> buffer(computer_size);
    if (libevt_record_get_utf8_computer_name(
            record, reinterpret_cast<uint8_t*>(buffer.data()), computer_size,
            &error) == 1) {
      event_data->setComputer(buffer.data());
    } else if (error) {
      libevt_error_free(&error);
    }
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение SID пользователя
  size_t sid_size = 0;
  if (libevt_record_get_utf8_user_security_identifier_size(record, &sid_size,
                                                           &error) == 1 &&
      sid_size > 0) {
    std::vector<char> buffer(sid_size);
    if (libevt_record_get_utf8_user_security_identifier(
            record, reinterpret_cast<uint8_t*>(buffer.data()), sid_size,
            &error) == 1) {
      event_data->setUserSid(buffer.data());
    } else if (error) {
      libevt_error_free(&error);
    }
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение строковых данных события
  int number_of_strings = 0;
  if (libevt_record_get_number_of_strings(record, &number_of_strings, &error) ==
      1) {
    std::ostringstream description_stream;

    for (int i = 0; i < number_of_strings; i++) {
      size_t string_size = 0;
      if (libevt_record_get_utf8_string_size(record, i, &string_size, &error) ==
              1 &&
          string_size > 0) {
        std::vector<char> buffer(string_size);
        if (libevt_record_get_utf8_string(
                record, i, reinterpret_cast<uint8_t*>(buffer.data()),
                string_size, &error) == 1) {
          const std::string str_value = buffer.data();
          event_data->addData("String" + std::to_string(i), str_value);

          // Формируем описание из всех строк
          if (!description_stream.str().empty()) {
            description_stream << " | ";
          }
          description_stream << str_value;
        } else if (error) {
          libevt_error_free(&error);
        }
      } else if (error) {
        libevt_error_free(&error);
      }
    }

    // Установка описания
    if (!description_stream.str().empty()) {
      event_data->setDescription(description_stream.str());
    }
  } else if (error) {
    libevt_error_free(&error);
  }

  // Получение бинарных данных
  size_t data_size = 0;
  if (libevt_record_get_data_size(record, &data_size, &error) == 1 &&
      data_size > 0) {
    std::vector<uint8_t> buffer(data_size);
    if (libevt_record_get_data(record, buffer.data(), data_size, &error) == 1) {
      event_data->setBinaryData(std::move(buffer));
    } else if (error) {
      libevt_error_free(&error);
    }
  } else if (error) {
    libevt_error_free(&error);
  }

  return event_data;
}

std::vector<std::unique_ptr<IEventData>> EvtParser::parseEvents(
    const std::string& file_path) {
  const auto logger = GlobalLogger::get();
  logger->debug("Разбор событий из EVT файла: \"{}\"", file_path);

  try {
    OpenLogFile(file_path);

    libevt_error_t* error = nullptr;
    int record_count = 0;
    std::vector<std::unique_ptr<IEventData>> events;

    // Получение количества записей
    if (libevt_file_get_number_of_records(evt_file_, &record_count, &error) !=
        1) {
      std::string error_msg = "Не удалось получить количество записей";
      if (error) {
        char error_buffer[256];
        libevt_error_sprint(error, error_buffer, sizeof(error_buffer));
        error_msg += ": "s + error_buffer;
        libevt_error_free(&error);
      }
      logger->error(error_msg);
      throw DataReadException(error_msg);
    }

    logger->debug("Найдено \"{}\" записей в EVT файле", record_count);

    // Получение всех записей
    for (int i = 0; i < record_count; i++) {
      libevt_record_t* record = nullptr;
      if (libevt_file_get_record_by_index(evt_file_, i, &record, &error) == 1) {
        events.push_back(ParseRecord(record));
        libevt_record_free(&record, nullptr);
      } else if (error) {
        libevt_error_free(&error);
      }
    }

    logger->debug("Успешно разобрано \"{}\" событий", events.size());
    return events;
  } catch (...) {
    CloseLogFile();
    throw;
  }
}

std::vector<std::unique_ptr<IEventData>> EvtParser::getEventsByType(
    const std::string& file_path, uint32_t event_id) {
  const auto logger = GlobalLogger::get();
  logger->debug("Фильтрация событий по ID \"{}\" из EVT файла: \"{}\"", event_id,
               file_path);

  try {
    OpenLogFile(file_path);

    libevt_error_t* error = nullptr;
    int record_count = 0;
    std::vector<std::unique_ptr<IEventData>> filtered_events;

    // Получение количества записей
    if (libevt_file_get_number_of_records(evt_file_, &record_count, &error) !=
        1) {
      std::string error_msg = "Не удалось получить количество записей";
      if (error) {
        char error_buffer[256];
        libevt_error_sprint(error, error_buffer, sizeof(error_buffer));
        error_msg += ": "s + error_buffer;
        libevt_error_free(&error);
      }
      logger->error(error_msg);
      throw DataReadException(error_msg);
    }

    logger->debug("Найдено \"{}\" записей в EVT файле", record_count);

    // Фильтрация записей по ID события
    for (int i = 0; i < record_count; i++) {
      libevt_record_t* record = nullptr;
      if (libevt_file_get_record_by_index(evt_file_, i, &record, &error) == 1) {
        uint32_t current_id = 0;
        if (libevt_record_get_event_identifier(record, &current_id, nullptr) ==
                1 &&
            current_id == event_id) {
          filtered_events.push_back(ParseRecord(record));
        }
        libevt_record_free(&record, nullptr);
      } else if (error) {
        libevt_error_free(&error);
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
