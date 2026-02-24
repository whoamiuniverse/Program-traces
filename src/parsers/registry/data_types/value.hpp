/// @file value.hpp
/// @brief RAII-обёртка для управления значениями реестра Windows

#pragma once

#include <libregf.h>

namespace RegistryAnalysis {

/// @class ValueHandle
/// @brief Умный указатель для управления ресурсами libregf_value_t
/// @details Обеспечивает безопасное владение указателем на libregf_value_t,
/// автоматически освобождая ресурсы при разрушении объекта
class ValueHandle {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор
  /// @param[in] value Указатель на libregf_value_t (может быть nullptr)
  explicit ValueHandle(libregf_value_t* value = nullptr) noexcept;

  /// @brief Деструктор
  ~ValueHandle();

  /// @brief Перемещающий конструктор
  /// @param[in] other Объект для перемещения
  ValueHandle(ValueHandle&& other) noexcept;

  /// @brief Перемещающий оператор присваивания
  /// @param[in] other Объект для перемещения
  ValueHandle& operator=(ValueHandle&& other) noexcept;

  /// @brief Запрет копирования
  ValueHandle(const ValueHandle&) = delete;

  /// @brief Запрет копирующего присваивания
  ValueHandle& operator=(const ValueHandle&) = delete;

  /// @}

  /// @name Методы доступа
  ///@{

  /// @brief Получить владеемый указатель
  /// @return Сырой указатель на libregf_value_t
  libregf_value_t* getPtr() const noexcept;

  /// @brief Установить новый указатель
  /// @param[in] value Новый указатель (текущий освобождается)
  void setPtr(libregf_value_t* value) noexcept;

  /// @brief Получить адрес указателя
  /// @return Указатель на указатель (libregf_value_t**)
  libregf_value_t** getAddressOfPtr();

  /// @brief Проверка наличия указателя
  /// @return true если указатель не nullptr
  explicit operator bool() const noexcept;

  /// @}

 private:
  /// @brief Внутренняя функция освобождения ресурсов
  void reset() noexcept;

  libregf_value_t* ptr_ = nullptr;  ///< Указатель на значение реестра
};

}
