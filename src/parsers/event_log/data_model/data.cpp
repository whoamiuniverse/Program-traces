#include "data.hpp"

namespace EventLogAnalysis {

EventData::EventData()
    : event_id_(0),
      timestamp_(0),
      level_(EventLevel::LOG_ALWAYS),
      user_sid_("") {}

void EventData::setEventID(const uint32_t id) { event_id_ = id; }
void EventData::setTimestamp(const uint64_t timestamp) { timestamp_ = timestamp; }
void EventData::setLevel(const EventLevel level) { level_ = level; }
void EventData::setProvider(const std::string& provider) {
  provider_ = provider;
}
void EventData::setComputer(const std::string& computer) {
  computer_ = computer;
}
void EventData::setChannel(const std::string& channel) { channel_ = channel; }
void EventData::setDescription(const std::string& desc) { description_ = desc; }
void EventData::setXml(const std::string& xml) { xml_ = xml; }
void EventData::addData(const std::string& name, const std::string& value) {
  data_[name] = value;
}

void EventData::setUserSid(const std::string& sid) { user_sid_ = sid; }

void EventData::setBinaryData(std::vector<uint8_t>&& data) {
  binary_data_ = std::move(data);
}

uint32_t EventData::getEventID() const { return event_id_; }
uint64_t EventData::getTimestamp() const { return timestamp_; }
EventLevel EventData::getLevel() const { return level_; }
const std::string& EventData::getProvider() const { return provider_; }
const std::string& EventData::getComputer() const { return computer_; }
const std::string& EventData::getChannel() const { return channel_; }
const std::string& EventData::getDescription() const { return description_; }
const std::unordered_map<std::string, std::string>& EventData::getData() const {
  return data_;
}
const std::string& EventData::getXmlRepresentation() const { return xml_; }

const std::string& EventData::getUserSid() const { return user_sid_; }

const std::vector<uint8_t>& EventData::getBinaryData() const {
  return binary_data_;
}

}
