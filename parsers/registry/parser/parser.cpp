#include "parser.hpp"

#include <libregf.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "../../../core/exceptions/parsing_exception.hpp"
#include "../../../core/exceptions/registry_exception.hpp"
#include "../../../utils/logging/logger.hpp"
#include "../data_model/data.hpp"
#include "../data_model/data_builder.hpp"
#include "../data_types/key.hpp"
#include "../data_types/value.hpp"

namespace RegistryAnalysis {

RegistryParser::~RegistryParser() {
  const auto logger = GlobalLogger::get();
  closeRegistryFile();
}

std::vector<std::unique_ptr<IRegistryData>> RegistryParser::getKeyValues(
    const std::string& registry_file_path,
    const std::string& registry_key_path) {
  const auto logger = GlobalLogger::get();

  logger->debug("Начало обработки файла реестра: \"{}\"", registry_file_path);
  logger->debug("Получение значений ключа \"{}\" из \"{}\"", registry_key_path,
                registry_file_path);

  openRegistryFile(registry_file_path);
  KeyHandle key_handle = findRegistryKey(registry_key_path);
  std::vector<std::unique_ptr<IRegistryData>> results;

  // Получаем количество значений в ключе
  int32_t value_count = 0;
  if (libregf_key_get_number_of_values(key_handle.getPtr(), &value_count,
                                       nullptr) != 1) {
    logger->debug("Не удалось получить количество значений для ключа: \"{}\"",
                  registry_key_path);
    return results;
  }

  logger->debug("Найдено значений в ключе: \"{}\"", value_count);

  // Обрабатываем все значения в ключе
  for (int value_index = 0; value_index < value_count; ++value_index) {
    logger->debug("Начало обработки значения с индексом: \"{}\"", value_index);

    ValueHandle value_handle;
    if (libregf_key_get_value_by_index(key_handle.getPtr(), value_index,
                                       value_handle.getAddressOfPtr(),
                                       nullptr) != 1) {
      logger->debug("Не удалось получить значение по индексу: \"{}\"",
                    value_index);
      continue;  // Пропускаем недоступные значения
    }

    // Извлекаем имя значения
    size_t name_buffer_size = 0;
    if (libregf_value_get_utf8_name_size(value_handle.getPtr(),
                                         &name_buffer_size, nullptr) != 1) {
      logger->debug("Не удалось получить размер имени значения");
      continue;
    }

    std::string actual_value_name;
    if (name_buffer_size > 0) {
      std::vector<char> name_buffer(name_buffer_size);
      if (libregf_value_get_utf8_name(
              value_handle.getPtr(),
              reinterpret_cast<uint8_t*>(name_buffer.data()), name_buffer_size,
              nullptr) == 1) {
        // Определяем фактическую длину строки
        const size_t actual_length =
            strnlen(name_buffer.data(), name_buffer_size);
        actual_value_name.assign(name_buffer.data(), actual_length);
        logger->debug("Имя значения: \"{}\"", actual_value_name);
      }
    } else {
      logger->debug("Значение не имеет имени (по умолчанию)");
    }

    // Формируем полный путь к значению
    std::string full_value_path = registry_key_path;
    if (!actual_value_name.empty()) {
      full_value_path += '/';
      full_value_path += actual_value_name;
    } else {
      full_value_path += "/";
    }
    logger->debug("Полный путь к значению: \"{}\"", full_value_path);

    // Создаем объект данных
    try {
      if (auto data_object = createRegistryDataObject(value_handle.getPtr(),
                                                      full_value_path)) {
        results.push_back(std::move(data_object));
      } else {
        logger->debug("Не удалось создать объект данных для значения");
      }
    } catch (const RegistryException& e) {
      logger->error("Ошибка при создании объекта данных: \"{}\"", e.what());
    }
  }

  logger->debug("Возвращено \"{}\" значений для ключа: \"{}\"", results.size(),
                registry_key_path);
  logger->debug("Файл успешно обработан");
  return results;
}

void RegistryParser::openRegistryFile(const std::string& registry_file_path) {
  const auto logger = GlobalLogger::get();

  if (regf_file_handle_) {
    closeRegistryFile();
  }

  if (libregf_file_initialize(&regf_file_handle_, nullptr) != 1) {
    throw InitLibError("libregf");
  }

  logger->debug("Открытие файла: \"{}\"", registry_file_path);

  if (libregf_file_open(regf_file_handle_, registry_file_path.c_str(),
                        LIBREGF_OPEN_READ, nullptr) != 1) {
    libregf_file_free(&regf_file_handle_, nullptr);
    throw FileOpenException(registry_file_path);
  }

  logger->debug("Файл реестра успешно открыт");
}

void RegistryParser::closeRegistryFile() {
  const auto logger = GlobalLogger::get();

  if (regf_file_handle_) {
    libregf_file_free(&regf_file_handle_, nullptr);
    regf_file_handle_ = nullptr;
    logger->debug("Файл реестра закрыт");
  }
}

KeyHandle RegistryParser::findRegistryKey(const std::string& key_path) const {
  const auto logger = GlobalLogger::get();
  logger->debug("Поиск ключа реестра: \"{}\"", key_path);

  if (!regf_file_handle_) {
    throw RegistryNotOpenError("файл реестра не открыт");
  }

  KeyHandle current_key;

  if (libregf_file_get_root_key(regf_file_handle_,
                                current_key.getAddressOfPtr(), nullptr) != 1) {
    throw RootKeyError("не удалось получить корневой ключ");
  }

  // Пустой путь - возвращаем корневой ключ
  if (key_path.empty()) {
    logger->debug("Запрошен пустой путь, возвращаем корневой ключ");
    return current_key;
  }

  constexpr char path_separators[] = "/\\";
  size_t start_pos = 0;
  size_t end_pos = key_path.find_first_of(path_separators);

  while (end_pos != std::string::npos) {
    if (end_pos > start_pos) {
      const std::string key_component =
          key_path.substr(start_pos, end_pos - start_pos);

      logger->debug("Обработка компонента: \"{}\"", key_component);

      KeyHandle next_key;
      const auto* name_ptr =
          reinterpret_cast<const uint8_t*>(key_component.c_str());

      if (libregf_key_get_sub_key_by_utf8_name(
              current_key.getPtr(), name_ptr, key_component.size(),
              next_key.getAddressOfPtr(), nullptr) != 1) {
        throw KeyNotFoundError(key_component, key_path);
      }
      current_key = std::move(next_key);
    }
    start_pos = end_pos + 1;
    end_pos = key_path.find_first_of(path_separators, start_pos);
  }

  // Обработка последнего компонента пути
  if (start_pos < key_path.size()) {
    const std::string last_component = key_path.substr(start_pos);
    logger->debug("Обработка последнего компонента: \"{}\"", last_component);

    KeyHandle next_key;
    const auto* name_ptr =
        reinterpret_cast<const uint8_t*>(last_component.c_str());

    if (libregf_key_get_sub_key_by_utf8_name(
            current_key.getPtr(), name_ptr, last_component.size(),
            next_key.getAddressOfPtr(), nullptr) != 1) {
      throw KeyNotFoundError(last_component, key_path);
    }
    current_key = std::move(next_key);
  }

  logger->debug("Ключ успешно найден: \"{}\"", key_path);
  return current_key;
}

ValueHandle RegistryParser::findRegistryValue(libregf_key_t* registry_key,
                                              const std::string& value_name) {
  const auto logger = GlobalLogger::get();
  logger->debug("Поиск значения: \"{}\"", value_name);

  if (!registry_key) {
    throw RegistryException("Передан нулевой указатель на ключ реестра");
  }

  ValueHandle value_handle;
  const uint8_t* name_ptr =
      value_name.empty() ? nullptr
                         : reinterpret_cast<const uint8_t*>(value_name.c_str());

  const size_t name_length = value_name.empty() ? 0 : value_name.size();

  logger->debug("Поиск значения в ключе реестра");
  if (libregf_key_get_value_by_utf8_name(registry_key, name_ptr, name_length,
                                         value_handle.getAddressOfPtr(),
                                         nullptr) != 1) {
    logger->debug("Значение не найдено: \"{}\"", value_name);
    return ValueHandle();  // Возвращаем пустой handle
  }

  logger->debug("Значение найдено: \"{}\"", value_name);
  return value_handle;
}

std::unique_ptr<IRegistryData> RegistryParser::getSpecificValue(
    const std::string& registry_file_path,
    const std::string& registry_value_path) {
  const auto logger = GlobalLogger::get();

  logger->debug("Получение конкретного значения: \"{}\"", registry_value_path);
  openRegistryFile(registry_file_path);

  // Разделяем путь на ключ и имя значения
  const size_t last_separator = registry_value_path.find_last_of("/\\");
  if (last_separator == std::string::npos) {
    throw InvalidPathError(registry_value_path);
  }

  const std::string key_path = registry_value_path.substr(0, last_separator);
  const std::string value_name = registry_value_path.substr(last_separator + 1);

  logger->debug("Путь к ключу \"{}\", имя значения \"{}\"", key_path,
                value_name);

  KeyHandle key_handle = findRegistryKey(key_path);
  ValueHandle value_handle = findRegistryValue(key_handle.getPtr(), value_name);

  if (!value_handle) {
    logger->debug("Значение не найдено: \"{}\"", registry_value_path);
    return nullptr;
  }

  logger->debug("Значение найдено создание объекта данных");
  return createRegistryDataObject(value_handle.getPtr(), registry_value_path);
}

std::vector<std::string> RegistryParser::listSubkeys(
    const std::string& registry_file_path,
    const std::string& registry_key_path) {
  const auto logger = GlobalLogger::get();
  logger->debug("Получение подразделов для ключа: \"{}\"", registry_key_path);

  // Открываем файл реестра
  openRegistryFile(registry_file_path);

  // Получаем handle родительского ключа
  KeyHandle parent_key = findRegistryKey(registry_key_path);

  std::vector<std::string> subkeys;
  int subkey_count = 0;

  // Получаем количество подразделов
  if (libregf_key_get_number_of_sub_keys(parent_key.getPtr(), &subkey_count, nullptr) != 1) {
    logger->debug("Не удалось получить количество подразделов для ключа: \"{}\"", registry_key_path);
    return subkeys;
  }

  logger->debug("Найдено подразделов: \"{}\"", subkey_count);

  // Перебираем все подразделы
  for (int i = 0; i < subkey_count; i++) {
    KeyHandle subkey;

    // Используем НЕ устаревший метод для получения подраздела по индексу
    if (libregf_key_get_sub_key_by_index(
            parent_key.getPtr(),
            i,
            subkey.getAddressOfPtr(),
            nullptr) != 1) {
      logger->debug("Не удалось получить подраздел с индексом: \"{}\"", i);
      continue;
    }

    // Получаем размер имени подраздела
    size_t name_size = 0;
    if (libregf_key_get_utf8_name_size(subkey.getPtr(), &name_size, nullptr) != 1) {
      logger->debug("Не удалось получить размер имени подраздела");
      continue;
    }

    // Пропускаем пустые имена
    if (name_size == 0) {
      continue;
    }

    // Читаем имя подраздела
    std::vector<char> name_buffer(name_size);
    if (libregf_key_get_utf8_name(
            subkey.getPtr(),
            reinterpret_cast<uint8_t*>(name_buffer.data()),
            name_size,
            nullptr) != 1) {
      logger->debug("Не удалось прочитать имя подраздела");
      continue;
    }

    // Определяем фактическую длину строки
    const size_t actual_length = strnlen(name_buffer.data(), name_size);
    subkeys.emplace_back(name_buffer.data(), actual_length);
    logger->debug("Найден подраздел: \"{}\"", subkeys.back());
  }

  logger->debug("Возвращено \"{}\" подразделов для ключа: \"{}\"",
                subkeys.size(), registry_key_path);
  return subkeys;
}

std::unique_ptr<IRegistryData> RegistryParser::createRegistryDataObject(
    libregf_value_t* value_handle, const std::string& value_path) {
  const auto logger = GlobalLogger::get();

  RegistryDataBuilder builder;

  builder.setName(value_path);
  processValueData(value_handle, builder);
  auto result = builder.build();

  if (result) {
    logger->debug("Конец обработки значения");
  } else {
    logger->debug("Не удалось обработать значение");
  }

  return result;
}

RegistryValueType RegistryParser::convertValueType(uint32_t libregf_type) {
  const auto logger = GlobalLogger::get();

  switch (libregf_type) {
    case LIBREGF_VALUE_TYPE_STRING:
      return RegistryValueType::REG_SZ;
    case LIBREGF_VALUE_TYPE_EXPANDABLE_STRING:
      return RegistryValueType::REG_EXPAND_SZ;
    case LIBREGF_VALUE_TYPE_BINARY_DATA:
      return RegistryValueType::REG_BINARY;
    case LIBREGF_VALUE_TYPE_INTEGER_32BIT_LITTLE_ENDIAN:
      return RegistryValueType::REG_DWORD;
    case LIBREGF_VALUE_TYPE_INTEGER_32BIT_BIG_ENDIAN:
      return RegistryValueType::REG_DWORD_BIG_ENDIAN;
    case LIBREGF_VALUE_TYPE_INTEGER_64BIT_LITTLE_ENDIAN:
      return RegistryValueType::REG_QWORD;
    case LIBREGF_VALUE_TYPE_MULTI_VALUE_STRING:
      return RegistryValueType::REG_MULTI_SZ;
    case LIBREGF_VALUE_TYPE_SYMBOLIC_LINK:
      return RegistryValueType::REG_LINK;
    case LIBREGF_VALUE_TYPE_RESOURCE_LIST:
      return RegistryValueType::REG_RESOURCE_LIST;
    case LIBREGF_VALUE_TYPE_UNDEFINED:
    default:
      logger->debug("Неизвестный или неподдерживаемый тип реестра: \"{}\"",
                    libregf_type);
      return RegistryValueType::REG_NONE;
  }
}

void RegistryParser::processValueData(libregf_value_t* value_handle,
                                      RegistryDataBuilder& builder) {
  const auto logger = GlobalLogger::get();

  uint32_t raw_value_type = 0;
  if (libregf_value_get_value_type(value_handle, &raw_value_type, nullptr) !=
      1) {
    logger->debug("Не удалось получить тип значения");
    return;
  }

  const RegistryValueType value_type = convertValueType(raw_value_type);
  logger->debug("Обработка данных значения. Тип значения: \"{}\"",
                static_cast<uint32_t>(value_type));

  // Обработка строковых значений
  if (value_type == RegistryValueType::REG_SZ ||
      value_type == RegistryValueType::REG_EXPAND_SZ) {
    size_t data_size = 0;
    if (libregf_value_get_value_data_size(value_handle, &data_size, nullptr) !=
            1 ||
        data_size == 0) {
      // Пустая строка
      if (value_type == RegistryValueType::REG_SZ) {
        builder.setString("");
      } else {
        builder.setExpandString("");
      }
      return;
    }

    std::vector<uint8_t> buffer(data_size);
    if (libregf_value_get_value_utf8_string(value_handle, buffer.data(),
                                            buffer.size(), nullptr) == 1) {
      const auto str_start = reinterpret_cast<const char*>(buffer.data());
      const size_t actual_length = strnlen(str_start, data_size);
      const std::string string_data(str_start, actual_length);

      if (value_type == RegistryValueType::REG_SZ) {
        builder.setString(string_data);
      } else {
        builder.setExpandString(string_data);
      }
    } else {
      logger->debug("Не удалось прочитать строковое значение");
    }
    return;
  }

  // Получение данных для остальных типов
  size_t data_size = 0;
  if (libregf_value_get_value_data_size(value_handle, &data_size, nullptr) !=
          1 ||
      data_size == 0) {
    logger->debug(
        "Не удалось получить размер данных значения или размер равен нулю");
    return;
  }

  logger->debug("Размер данных значения: \"{}\"", data_size);
  std::vector<uint8_t> data_buffer(data_size);
  if (libregf_value_get_value_data(value_handle, data_buffer.data(), data_size,
                                   nullptr) != 1) {
    logger->debug("Не удалось получить данные значения");
    return;
  }

  // Обработка конкретных типов данных
  switch (value_type) {
    case RegistryValueType::REG_BINARY:
      builder.setBinary(data_buffer);
      break;

    case RegistryValueType::REG_DWORD:
      if (data_size >= sizeof(uint32_t)) {
        uint32_t dword_value;
        memcpy(&dword_value, data_buffer.data(), sizeof(dword_value));
        builder.setDword(dword_value);
      } else {
        logger->debug("Некорректный размер данных для DWORD: \"{}\"",
                      data_size);
      }
      break;

    case RegistryValueType::REG_DWORD_BIG_ENDIAN:
      if (data_size >= sizeof(uint32_t)) {
        const uint32_t dword_value =
            static_cast<uint32_t>(data_buffer[0]) << 24 |
            static_cast<uint32_t>(data_buffer[1]) << 16 |
            static_cast<uint32_t>(data_buffer[2]) << 8 |
            static_cast<uint32_t>(data_buffer[3]);
        builder.setDwordBigEndian(dword_value);
      } else {
        logger->debug("Некорректный размер данных для big-endian DWORD: \"{}\"",
                      data_size);
      }
      break;

    case RegistryValueType::REG_QWORD:
      if (data_size >= sizeof(uint64_t)) {
        uint64_t qword_value;
        memcpy(&qword_value, data_buffer.data(), sizeof(qword_value));
        builder.setQword(qword_value);
      } else {
        logger->debug("Некорректный размер данных для QWORD: \"{}\"",
                      data_size);
      }
      break;

    case RegistryValueType::REG_MULTI_SZ: {
      std::vector<std::string> strings;
      const char* current_pos =
          reinterpret_cast<const char*>(data_buffer.data());
      const char* end_pos = current_pos + data_size;

      while (current_pos < end_pos) {
        const size_t string_length =
            strnlen(current_pos, end_pos - current_pos);
        if (string_length == 0) break;

        strings.emplace_back(current_pos, string_length);
        current_pos += string_length + 1;

        // Проверка на двойной нулевой терминатор
        if (current_pos < end_pos && *current_pos == '\0') break;
      }
      builder.setMultiString(strings);
      break;
    }

    default:
      logger->debug("Неподдерживаемый тип значения для обработки: \"{}\"",
                    static_cast<uint32_t>(value_type));
      break;
  }
}

}
