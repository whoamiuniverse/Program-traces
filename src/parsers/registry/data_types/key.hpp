/// @file key.hpp
/// @brief RAII-обертка для управления ключами реестра Windows

#pragma once

#include <libregf.h>

namespace RegistryAnalysis {

/// @class KeyHandle
/// @brief Умный указатель для работы с ключами реестра libregf_key_t
/// @details Обеспечивает безопасное управление временем жизни ключа реестра,
/// автоматически освобождая ресурсы при разрушении объекта
class KeyHandle {
 public:
  /// @name Основные методы класса
  /// @{

  /// @brief Конструктор с необязательным начальным указателем
  /// @param[in] key Указатель на libregf_key_t (может быть nullptr)
  explicit KeyHandle(libregf_key_t* key = nullptr) noexcept;

  /// @brief Деструктор - автоматически освобождает ресурсы
  ~KeyHandle();

  /// @brief Перемещающий конструктор
  /// @param[in] other Объект для перемещения
  KeyHandle(KeyHandle&& other) noexcept;

  /// @brief Перемещающий оператор присваивания
  /// @param[in] other Объект для перемещения
  KeyHandle& operator=(KeyHandle&& other) noexcept;

  /// @brief Запрет копирования
  KeyHandle(const KeyHandle&) = delete;

  /// @brief Запрет копирующего присваивания
  KeyHandle& operator=(const KeyHandle&) = delete;

  /// @}

  /// @name Методы доступа
  ///@{

  /// @brief Получить хранимый указатель
  /// @return Сырой указатель на libregf_key_t
  libregf_key_t* getPtr() const noexcept;

  /// @brief Установить новый указатель
  /// @param[in] key Новый указатель (старый освобождается)
  void setPtr(libregf_key_t* key) noexcept;

  /// @brief Получить адрес указателя
  /// @return Указатель на указатель (libregf_key_t**)
  libregf_key_t** getAddressOfPtr();

  /// @brief Проверка наличия валидного указателя
  /// @return true если указатель не nullptr
  explicit operator bool() const noexcept;

  /// @}

 private:
  /// @brief Внутренняя функция освобождения ресурсов
  void reset() noexcept;

  libregf_key_t* ptr_ = nullptr;  ///< Указатель на ключ реестра
};

}  // namespace RegistryAnalysis
