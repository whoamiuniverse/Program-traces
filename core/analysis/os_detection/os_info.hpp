/// @file os_info.hpp
/// @brief Структура для хранения детальной информации об операционной системе

#pragma once

#include <string>

/// @brief Структура для хранения детальной информации об операционной системе
/// @details Содержит все основные параметры ОС, включая версию, сборку и
/// редакцию
struct OSInfo {
  std::string product_name;  ///< Полное название продукта ОС (например "Windows
                             ///< 11 Pro" или "Ubuntu 22.04 LTS")
  std::string current_version;  ///< Основной номер версии ОС (формат "10.0" для
                                ///< Windows 10/11)
  std::string edition_id;  ///< Идентификатор редакции (например "Professional",
                           ///< "Enterprise", "Home")
  std::string current_build;  ///< Номер сборки ОС (например "22000" для Windows
                              ///< 11 21H2)
  std::string
      release_id;  ///< Идентификатор выпуска (например "21H2" для Windows)
  std::string display_version;  ///< Отображаемая версия для пользователя
                                ///< (например "21H2", "22H2")
  std::string
      fullname_os;  ///< Полное системное название ОС с деталями (например
                    ///< "Microsoft Windows 11 Pro 10.0.22000")
  std::string ini_version; ///< Версия ОС, расположенная в .ini файлах
};

/// @brief Конфигурация для определения версии ОС
struct VersionConfig {
  std::string registry_file;  ///< Путь к файлу реестра
  std::string registry_key;   ///< Путь к ключу в реестре
  std::vector<std::string>
      registry_keys;  ///< Список имен параметров реестра для извлечения
};
