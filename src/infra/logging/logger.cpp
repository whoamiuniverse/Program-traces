#include "logger.hpp"

#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <iostream>

#include "logger_exception.hpp"

namespace fs = std::filesystem;

std::string GlobalLogger::log_path_ = "logs/app.log";
std::shared_ptr<spdlog::logger> GlobalLogger::logger_ = nullptr;
std::mutex GlobalLogger::init_mutex_;
std::once_flag GlobalLogger::init_flag_;

void GlobalLogger::setLogPath(const std::string& path) {
  std::lock_guard lock(init_mutex_);

  if (logger_) {
    throw std::logic_error(
        "Невозможно изменить путь к логам после инициализации логгера");
  }

  log_path_ = path;
}

void GlobalLogger::initialize() {
  try {
    constexpr size_t MAX_SIZE = 5 * 1024 * 1024;  // 5 MB
    constexpr size_t MAX_FILES = 3;

    // Создание директорий для логов
    fs::path log_path(log_path_);
    auto parent_dir = log_path.parent_path();

    if (!parent_dir.empty()) {
      std::error_code ec;
      fs::create_directories(parent_dir, ec);

      if (ec) {
        throw LoggerInitException("Ошибка создания директории для логов '" +
                                  parent_dir.string() + "': " + ec.message());
      }
    }

    // Создаем слоты (sinks)
    std::vector<spdlog::sink_ptr> sinks;

    // 1. Слот для записи ВСЕХ уровней в файл
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_path_, MAX_SIZE, MAX_FILES);
    file_sink->set_level(spdlog::level::trace);
    file_sink->set_pattern("[%Y-%m-%d %T.%e] [%l] [%s:%#] %v");
    sinks.push_back(file_sink);

    // 2. Слот для вывода в консоль (только info и выше)
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::info);
    console_sink->set_pattern("%^[%Y-%m-%d %T] [%l]%$ %v");
    sinks.push_back(console_sink);

    // Создаем логгер с двумя слотами
    logger_ =
        std::make_shared<spdlog::logger>("global", sinks.begin(), sinks.end());
    logger_->set_level(spdlog::level::trace);
    logger_->flush_on(spdlog::level::warn);

    // Регистрация обработчика ошибок
    spdlog::set_error_handler([](const std::string& msg) {
      throw LoggerInitException("Ошибка spdlog: " + msg);
    });

    logger_->info("Логгер успешно инициализирован");
    logger_->debug("Путь к логам: \"{}\"", log_path_);

  } catch (const spdlog::spdlog_ex& ex) {
    throw LoggerInitException("Исключение spdlog: " + std::string(ex.what()));
  } catch (const fs::filesystem_error& ex) {
    throw LoggerInitException("Файловая система: " + std::string(ex.what()));
  } catch (const std::exception& ex) {
    throw LoggerInitException("Ошибка инициализации: " +
                              std::string(ex.what()));
  }
}

std::shared_ptr<spdlog::logger> GlobalLogger::get() {
  std::call_once(init_flag_, [] {
    try {
      initialize();
    } catch (const LoggerInitException& ex) {
      // Попытка создать fallback логгер
      try {
        // Вариант 1: stdout с цветной маркировкой
        auto console_sink =
            std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("%^[%Y-%m-%d %T] [%l]%$ %v");

        logger_ = std::make_shared<spdlog::logger>("fallback", console_sink);
        logger_->set_level(spdlog::level::info);
        logger_->error("Ошибка инициализации основного логгера: {}", ex.what());
        logger_->warn("Используется резервный логгер (консольный)");
      } catch (...) {
        // Вариант 2: null sink (никакого вывода)
        try {
          auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
          logger_ = std::make_shared<spdlog::logger>("null", null_sink);
          std::cerr << "Ошибка инициализации резервного логгера. Логирование "
                       "отключено."
                    << std::endl;
        } catch (...) {
          // Финальный запасной вариант
          spdlog::set_pattern("%v");
          logger_ = spdlog::default_logger();
          logger_->set_level(spdlog::level::off);
          std::cerr
              << "Критическая ошибка инициализации логгера. Все логи отключены."
              << std::endl;
        }
      }
    }
  });

  return logger_;
}
