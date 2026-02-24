/// @file data.hpp
/// @brief Конкретная модель события Windows Event Log
/// @details Реализует интерфейс `IEventData` и хранит все извлечённые поля
/// события в нормализованном виде.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "idata.hpp"

namespace EventLogAnalysis {

/// @class EventData
/// @brief Изменяемая реализация данных события журнала Windows
/// @details Используется парсерами EVT/EVTX как контейнер для поэтапного
/// заполнения полей события и последующего чтения через интерфейс `IEventData`.
class EventData final : public IEventData {
 public:
  /// @brief Создаёт пустой объект события
  /// @details После создания все числовые значения равны нулю, строки пустые.
  EventData();

  /// @brief Устанавливает идентификатор события
  /// @param id Значение Event ID из записи журнала
  void setEventID(uint32_t id);

  /// @brief Устанавливает временную метку события
  /// @param timestamp Время события в формате FILETIME/Unix (в зависимости от
  /// политики парсера, но единообразно в рамках проекта)
  void setTimestamp(uint64_t timestamp);

  /// @brief Устанавливает уровень важности события
  /// @param level Уровень из перечисления `EventLevel`
  void setLevel(EventLevel level);

  /// @brief Устанавливает имя провайдера события
  /// @param provider Источник события (например, `Microsoft-Windows-Security`)
  void setProvider(const std::string& provider);

  /// @brief Устанавливает имя компьютера-источника
  /// @param computer Имя хоста, на котором произошло событие
  void setComputer(const std::string& computer);

  /// @brief Устанавливает имя канала журнала
  /// @param channel Канал Event Log (например, `System`, `Security`)
  void setChannel(const std::string& channel);

  /// @brief Устанавливает текстовое описание события
  /// @param desc Текст сообщения события
  void setDescription(const std::string& desc);

  /// @brief Устанавливает полное XML-представление события
  /// @param xml XML-строка исходной записи
  void setXml(const std::string& xml);

  /// @brief Добавляет дополнительный параметр события
  /// @param name Имя параметра (ключ)
  /// @param value Значение параметра
  void addData(const std::string& name, const std::string& value);

  /// @brief Устанавливает SID пользователя, связанного с событием
  /// @param sid Строковое представление SID
  void setUserSid(const std::string& sid);

  /// @brief Устанавливает бинарный payload события
  /// @param data Массив байтов, перемещаемый во внутреннее хранилище
  void setBinaryData(std::vector<uint8_t>&& data);

  /// @copydoc IEventData::getEventID
  [[nodiscard]] uint32_t getEventID() const override;

  /// @copydoc IEventData::getTimestamp
  [[nodiscard]] uint64_t getTimestamp() const override;

  /// @copydoc IEventData::getLevel
  [[nodiscard]] EventLevel getLevel() const override;

  /// @copydoc IEventData::getProvider
  [[nodiscard]] const std::string& getProvider() const override;

  /// @copydoc IEventData::getComputer
  [[nodiscard]] const std::string& getComputer() const override;

  /// @copydoc IEventData::getChannel
  [[nodiscard]] const std::string& getChannel() const override;

  /// @copydoc IEventData::getDescription
  [[nodiscard]] const std::string& getDescription() const override;

  /// @copydoc IEventData::getData
  [[nodiscard]] const std::unordered_map<std::string, std::string>& getData()
      const override;

  /// @copydoc IEventData::getXmlRepresentation
  [[nodiscard]] const std::string& getXmlRepresentation() const override;

  /// @brief Возвращает SID пользователя события
  /// @return SID пользователя, если он присутствовал в записи
  [[nodiscard]] const std::string& getUserSid() const;

  /// @brief Возвращает бинарные данные события
  /// @return Константная ссылка на массив бинарного payload
  [[nodiscard]] const std::vector<uint8_t>& getBinaryData() const;

 private:
  uint32_t event_id_;  ///< Идентификатор события (Event ID)
  uint64_t timestamp_;  ///< Временная метка события
  EventLevel level_;    ///< Уровень серьёзности события
  std::string provider_;  ///< Имя провайдера/источника события
  std::string computer_;  ///< Имя компьютера-источника
  std::string channel_;  ///< Имя канала журнала
  std::string description_;  ///< Текстовое описание события
  std::string xml_;          ///< Полный XML записи события
  std::string user_sid_;  ///< SID пользователя, если присутствует
  std::vector<uint8_t> binary_data_;  ///< Бинарный payload записи
  std::unordered_map<std::string, std::string>
      data_;  ///< Произвольные пары ключ-значение из тела события
};

}
