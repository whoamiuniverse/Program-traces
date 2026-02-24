/// @file data.hpp
/// @brief Реализует интерфейс IEventData, хранящий все основные атрибуты
/// события Windows

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "idata.hpp"

namespace EventLogAnalysis {

class EventData final : public IEventData {
 public:
  EventData();

  void setEventID(uint32_t id);
  void setTimestamp(uint64_t timestamp);
  void setLevel(EventLevel level);
  void setProvider(const std::string& provider);
  void setComputer(const std::string& computer);
  void setChannel(const std::string& channel);
  void setDescription(const std::string& desc);
  void setXml(const std::string& xml);
  void addData(const std::string& name, const std::string& value);
  void setUserSid(const std::string& sid);
  void setBinaryData(std::vector<uint8_t>&& data);

  uint32_t getEventID() const override;
  uint64_t getTimestamp() const override;
  EventLevel getLevel() const override;
  const std::string& getProvider() const override;
  const std::string& getComputer() const override;
  const std::string& getChannel() const override;
  const std::string& getDescription() const override;
  const std::unordered_map<std::string, std::string>& getData() const override;
  const std::string& getXmlRepresentation() const override;
  const std::string& getUserSid() const;
  const std::vector<uint8_t>& getBinaryData() const;

 private:
  uint32_t event_id_;
  uint64_t timestamp_;
  EventLevel level_;
  std::string provider_;
  std::string computer_;
  std::string channel_;
  std::string description_;
  std::string xml_;
  std::string user_sid_;
  std::vector<uint8_t> binary_data_;
  std::unordered_map<std::string, std::string> data_;
};

}
