/// @file iparser.hpp
/// @brief Интерфейс для парсинга Prefetch-файлов Windows

#pragma once

#include <memory>
#include <string>

#include "parsers/prefetch/data_model/data_builder.hpp"

namespace PrefetchAnalysis {

/// @class IPrefetchParser
/// @brief Абстрактный базовый класс для парсеров Prefetch-файлов
/// @details Определяет основной интерфейс для всех реализаций парсеров
/// Prefetch-файлов. Обеспечивает единый контракт для различных реализаций
/// парсеров (например, на основе libscca или других библиотек).
/// @note Все реализации должны корректно обрабатывать следующие случаи:
///    - Поврежденные/неполные файлы
///    - Неподдерживаемые версии формата
///    - Ошибки ввода-вывода
class IPrefetchParser {
 public:
  /// @name Конструкторы/деструкторы
  /// @{

  /// @brief Виртуальный деструктор
  /// @details Гарантирует корректное удаление объектов производных классов
  /// через указатель на базовый класс
  virtual ~IPrefetchParser() noexcept = default;

  /// @}

  /// @name Основной интерфейс парсинга
  /// @{

  /// @brief Основной метод для парсинга Prefetch-файла
  /// @param[in] path Абсолютный путь к анализируемому файлу
  /// @return Уникальный указатель на объект с распарсенными данными
  /// @exception FileOpenException При проблемах с открытием файла
  /// @exception DataReadException При ошибках чтения данных
  /// @note Метод должен гарантировать:
  ///    - Освобождение всех ресурсов даже при возникновении исключений
  ///    - Корректную обработку nullptr при ошибках
  ///    - Полноту извлеченных данных (если файл не поврежден)
  [[nodiscard]] virtual std::unique_ptr<IPrefetchData> parse(
      const std::string& path) const = 0;

  /// @}
};

}
