#include "eventlog_analyzer.hpp"

#include <filesystem>

#include "../../../../utils/config/config.hpp"
#include "../../../../utils/logging/logger.hpp"
#include "../../../../utils/utils.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

EventLogAnalyzer::EventLogAnalyzer(
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evt_parser,
    std::unique_ptr<EventLogAnalysis::IEventLogParser> evtx_parser,
    std::string os_version, const std::string& ini_path)
    : evt_parser_(std::move(evt_parser)),
      evtx_parser_(std::move(evtx_parser)),
      os_version_(std::move(os_version)) {
  trim(os_version_);
  loadConfigurations(ini_path);
}

void EventLogAnalyzer::loadConfigurations(const std::string& ini_path) {
  Config config(ini_path, false, false);
  const auto logger = GlobalLogger::get();
  std::string versions_str = config.getString("General", "Versions", "");

  for (auto& version : split(versions_str, ',')) {
    trim(version);
    if (version.empty()) continue;

    EventLogConfig cfg;

    // Загрузка путей к журналам событий
    std::string log_paths = config.getString(version, "EventLogs", "");
    for (auto& path : split(log_paths, ',')) {
      trim(path);
      if (!path.empty()) {
        cfg.log_paths.push_back(path);
      }
    }

    // Загрузка ID событий о процессах
    std::string process_ids = config.getString(version, "ProcessEventIDs", "");
    for (auto& id_str : split(process_ids, ',')) {
      trim(id_str);
      if (!id_str.empty()) {
        try {
          cfg.process_event_ids.push_back(std::stoul(id_str));
        } catch (...) {
          logger->debug("Некорректный ID процесса: \"{}\"", id_str);
        }
      }
    }

    // Загрузка ID событий о сети
    std::string network_ids = config.getString(version, "NetworkEventIDs", "");
    for (auto& id_str : split(network_ids, ',')) {
      trim(id_str);
      if (!id_str.empty()) {
        try {
          cfg.network_event_ids.push_back(std::stoul(id_str));
        } catch (...) {
          logger->debug("Некорректный ID сети: \"{}\"", id_str);
        }
      }
    }

    configs_[version] = cfg;
    logger->debug("Загружена конфигурация журналов для \"{}\"", version);
  }
}

EventLogAnalysis::IEventLogParser* EventLogAnalyzer::getParserForFile(
    const std::string& file_path) const {
  const fs::path path = file_path;
  std::string ext = path.extension().string();

  // Преобразование расширения к нижнему регистру
  std::ranges::transform(ext, ext.begin(),
                         [](const unsigned char c) { return std::tolower(c); });

  if (ext == ".evt") {
    return evt_parser_.get();
  }
  if (ext == ".evtx") {
    return evtx_parser_.get();
  }

  return nullptr;
}

void EventLogAnalyzer::collect(
    const std::string& disk_root,
    std::map<std::string, ProcessInfo>& process_data,
    std::vector<NetworkConnection>& network_connections) {
  const auto logger = GlobalLogger::get();

  if (!configs_.contains(os_version_)) {
    logger->debug("Конфигурация журналов отсутствует для \"{}\"", os_version_);
    return;
  }

  for (const auto& cfg = configs_[os_version_];
       const auto& log_path : cfg.log_paths) {
    std::string full_dir_path = disk_root + log_path;

    // Проверяем существование и тип пути (директория/файл)
    if (!fs::exists(full_dir_path)) {
      logger->debug("Путь не существует: \"{}\"", full_dir_path);
      continue;
    }

    std::vector<std::string> files_to_parse;

    // Собираем файлы для обработки
    if (fs::is_directory(full_dir_path)) {
      for (const auto& entry : fs::directory_iterator(full_dir_path)) {
        if (entry.is_regular_file()) {
          files_to_parse.push_back(entry.path().string());
        }
      }
    } else if (fs::is_regular_file(full_dir_path)) {
      files_to_parse.push_back(full_dir_path);
    } else {
      logger->debug("Путь не является ни файлом, ни директорией: \"{}\"",
                   full_dir_path);
      continue;
    }

    // Обрабатываем собранные файлы
    for (const auto& file_path : files_to_parse) {
      if (!fs::exists(file_path)) {
        logger->debug("Файл был удалён: \"{}\"", file_path);
        continue;
      }

      auto* parser = getParserForFile(file_path);
      if (!parser) {
        logger->debug("Неизвестный формат журнала: \"{}\"", file_path);
        continue;
      }

      // Обработка событий о процессах
      for (const uint32_t event_id : cfg.process_event_ids) {
        try {
          for (const auto& event :
               parser->getEventsByType(file_path, event_id)) {
            const auto& data = event->getData();
            if (auto it = data.find("NewProcessName"); it != data.end()) {
              std::string name = it->second;
              ProcessInfo& info = process_data[name];
              info.filename = name;
              try {
                info.run_times.push_back(
                    convert_run_times(event->getTimestamp()));
              } catch (const std::exception& e) {
                logger->debug("{}", e.what());
              }
              info.run_count++;
            }
          }
        } catch (const std::exception& e) {
          logger->error("Ошибка парсинга событий о процессах ({}): {}",
                        file_path, e.what());
        }
      }

      // Обработка сетевых событий
      for (const uint32_t event_id : cfg.network_event_ids) {
        try {
          for (const auto& event :
               parser->getEventsByType(file_path, event_id)) {
            const auto& data = event->getData();
            NetworkConnection conn;
            if (data.contains("ProcessName")) {
              conn.process_name = data.at("ProcessName");
            } else {
              continue;
            }
            if (data.contains("LocalAddress")) {
              conn.local_address = data.at("LocalAddress");
            }
            if (data.contains("RemoteAddress")) {
              conn.remote_address = data.at("RemoteAddress");
            }
            if (data.contains("Port")) {
              try {
                conn.port = std::stoi(data.at("Port"));
              } catch (...) {
                conn.port = 0;
              }
            }
            if (data.contains("Protocol")) conn.protocol = data.at("Protocol");
            network_connections.push_back(conn);
          }
        } catch (const std::exception& e) {
          logger->error("Ошибка парсинга сетевых событий ({}): {}", file_path,
                        e.what());
        }
      }
    }
  }
}

}
