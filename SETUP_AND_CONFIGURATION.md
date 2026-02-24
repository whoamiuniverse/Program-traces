# Setup and configuration

Краткий справочник по структуре проекта, настройке `config.ini` и расширению поддержки версий Windows.

## Архитектура

```text
src/
  main.cpp                     # точка входа
  analysis/                    # сценарии анализа диска
    os/                        # определение версии/типа Windows
    artifacts/                 # анализ артефактов запуска ПО
  parsers/                     # адаптеры форматов (registry, prefetch, evt/evtx)
  errors/                      # типы исключений
  infra/                       # config, logging, export
  common/                      # общие утилиты (string/time/parse)
```

Зависимости по слоям:
- `main.cpp -> analysis`
- `analysis -> parsers + infra + errors + common`
- `parsers -> errors + common`
- `infra` и `common` не зависят от `analysis`

## Структура config.ini

Основные секции:
- `[General]` — список поддерживаемых версий (`Versions`).
- `[Logging]` — флаги детального debug по этапам анализа.
- `[CSVExport]` — правила экспорта и фильтрации CSV.
- `[OSInfo*]` — параметры определения версии Windows.
- `[VersionDefaults]` — базовые параметры артефактов для всех версий.
- `[WindowsXX]` — override только отличающихся параметров.

## Добавление Новой Версии Windows

1. Добавьте имя версии в `[General] -> Versions` в [config.ini](config.ini).
2. Если путь к `SOFTWARE` нестандартный, добавьте override в `[OSInfoRegistryPaths]`.
3. Создайте секцию `[<Version>]` и укажите только отличия от `[VersionDefaults]`.
4. При необходимости обновите `[BuildMappingsClient]` или `[BuildMappingsServer]`.
5. Запустите анализ и проверьте в логах строку `Версия Windows определена: ...`.

Минимальный пример:

```ini
[General]
Versions = WindowsXP,WindowsVista,Windows7,Windows8,Windows10,Windows11,WindowsServer,Windows12

[Windows12]
NetworkEventIDs = 5156,5157,3
```

## Генерация документации

```bash
sudo apt update && sudo apt install doxygen -y
doxygen docs/Doxyfile
```
