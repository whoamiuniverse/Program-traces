#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

#include "../../core/exceptions/config_exception.hpp"
#include "../../utils/logging/logger.hpp"

Config::Config(std::string filename, const bool useMultiKey,
               const bool useMultiLine)
    : ini_(std::make_shared<CSimpleIniA>()),
      filename_(std::move(filename)),
      useMultiKey_(useMultiKey),
      useMultiLine_(useMultiLine) {
  const auto logger = GlobalLogger::get();
  reload();
}

Config::Config(const Config& other) noexcept
    : ini_(other.ini_),
      filename_(other.filename_),
      useMultiKey_(other.useMultiKey_),
      useMultiLine_(other.useMultiLine_) {}

void Config::reload() const {
  const auto logger = GlobalLogger::get();

  // Настройка парсера через указатель
  ini_->SetMultiKey(useMultiKey_);
  ini_->SetMultiLine(useMultiLine_);
  ini_->SetUnicode(true);

  // Загрузка файла через указатель
  if (const SI_Error rc = ini_->LoadFile(filename_.c_str()); rc != SI_OK) {
    throw ConfigFileException(filename_);
  }
  logger->debug("Конфигурация успешно загружена");
}

std::string Config::getString(const std::string& section,
                              const std::string& key,
                              const std::string& defaultValue) const {
  const char* value =
      ini_->GetValue(section.c_str(), key.c_str(), defaultValue.c_str());
  if (!value) {
    throw ConfigValueException(section, key, "не удалось прочитать значение");
  }
  return value;
}

int Config::getInt(const std::string& section, const std::string& key,
                   const int defaultValue) const {
  const char* value = ini_->GetValue(section.c_str(), key.c_str(), nullptr);
  if (!value) {
    return defaultValue;
  }

  try {
    return std::stoi(value);
  } catch (const std::exception& e) {
    throw ConfigValueException(
        section, key,
        "не удалось преобразовать в целое число: " + std::string(e.what()));
  }
}

double Config::getDouble(const std::string& section, const std::string& key,
                         double defaultValue) const {
  const char* value = ini_->GetValue(section.c_str(), key.c_str(), nullptr);
  if (!value) {
    return defaultValue;
  }

  try {
    return std::stod(value);
  } catch (const std::exception& e) {
    throw ConfigValueException(section, key,
                               "не удалось преобразовать в число с плавающей "
                               "точкой: " +
                                   std::string(e.what()));
  }
}

bool Config::getBool(const std::string& section, const std::string& key,
                     const bool defaultValue) const {
  const char* value = ini_->GetValue(section.c_str(), key.c_str(), nullptr);

  if (!value) {
    return defaultValue;
  }

  std::string strValue(value);
  std::ranges::transform(strValue, strValue.begin(),
                         [](const unsigned char c) { return std::tolower(c); });

  if (strValue == "true" || strValue == "yes" || strValue == "on" ||
      strValue == "1") {
    return true;
  }
  if (strValue == "false" || strValue == "no" || strValue == "off" ||
      strValue == "0") {
    return false;
  }

  throw ConfigValueException(
      section, key, "недопустимое значение для булевого типа: " + strValue);
}

std::vector<std::pair<std::string, std::string>> Config::getAllValues(
    const std::string& section) const {
  const auto logger = GlobalLogger::get();
  std::vector<std::pair<std::string, std::string>> result;

  if (!hasSection(section)) {
    throw ConfigValueException(section, "", "секция не найдена");
  }

  if (CSimpleIniA::TNamesDepend keys; ini_->GetAllKeys(section.c_str(), keys)) {
    keys.sort(CSimpleIniA::Entry::LoadOrder());

    for (const auto& key : keys) {
      const char* value = ini_->GetValue(section.c_str(), key.pItem, "");
      result.emplace_back(key.pItem, value ? value : "");
    }
    logger->debug("Получено {} параметров из секции [{}]", result.size(),
                  section);
  }

  return result;
}

bool Config::hasSection(const std::string& section) const noexcept {
  return ini_->GetSectionSize(section.c_str()) > 0;
}

bool Config::hasKey(const std::string& section,
                    const std::string& key) const noexcept {
  return ini_->GetValue(section.c_str(), key.c_str(), nullptr) != nullptr;
}

std::vector<std::string> Config::getKeysInSection(
    const std::string& section_name) const {
  std::vector<std::string> keys;

  // Проверка существования секции
  if (!hasSection(section_name)) {
    return keys;
  }

  // Получаем все ключи из секции
  CSimpleIniA::TNamesDepend keysDepend;
  if (ini_->GetAllKeys(section_name.c_str(), keysDepend)) {
    // Сортировка по порядку загрузки (опционально)
    keysDepend.sort(CSimpleIniA::Entry::LoadOrder());

    // Преобразование в вектор строк
    keys.reserve(keysDepend.size());
    for (const auto& key : keysDepend) {
      keys.push_back(key.pItem);
    }
  }

  return keys;
}
