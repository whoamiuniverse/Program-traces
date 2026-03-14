# Configuration

## Overview

`config.ini` в репозитории уже упрощен: оставлены рабочие и часто используемые поля.
Этот документ описывает, как настроить файл без лишних опций.

## Quick Setup

1. Скопируйте `config.ini` как базовый профиль.
2. Проверьте порядок `General.Versions`.
3. Проверьте `VersionDefaults` (пути/ID для основных анализаторов).
4. Включите или выключите нужные источники в `Performance` и `Recovery`.
5. При необходимости задайте override-секции (`[Windows10]`, `[WindowsXP]` и т.д.).

## Config Model

Конфиг работает в два уровня:

1. Глобальные секции (`General`, `Performance`, `Recovery`, `VersionDefaults` и др.).
2. Версионные секции (`Windows11`, `Windows10`, `Windows7`, ...).

Fallback-правило:

1. Сначала берется значение из секции конкретной версии.
2. Если там ключ пустой или отсутствует, используется `VersionDefaults`.

## Minimal Fields In Current `config.ini`

### [General]

- `Versions` — порядок проверки версий Windows в детекторе ОС.

### [Logging]

- `DebugEventLog` — включает или выключает DEBUG-логи этапа EventLog.

### [Performance]

- `EnableParallelStages` — общий флаг параллельного выполнения независимых этапов.

### [OSInfoRegistryPaths]

- `Default` — путь к `SOFTWARE` hive по умолчанию.
- `WindowsXP` — путь к `SOFTWARE` hive для XP.
- `WindowsServer` — путь к `SOFTWARE` hive для server-линейки.

### [OSInfoSystemRegistryPaths]

- `Default` — путь к `SYSTEM` hive по умолчанию.
- `WindowsXP` — путь к `SYSTEM` hive для XP.
- `WindowsServer` — путь к `SYSTEM` hive для server-линейки.

### [OSInfoHive]

- `Default` — раздел реестра для определения версии ОС.

### [OSInfoKeys]

- `Default` — набор registry value, используемых в OS detection.

### [BuildMappingsClient]

- `<build> = <name>` — маппинг build-номера на клиентскую версию Windows.

### [BuildMappingsServer]

- `<build> = <name>` — маппинг build-номера на серверную версию Windows.

### [OSKeywords]

- `DefaultServerKeywords` — fallback-ключевые слова для server edition.

### [Recovery]

- `EnableUnallocated` — включить/выключить сканирование unallocated image.

### [VersionDefaults]

- `RegistryPath` — базовый путь к `SOFTWARE` hive для артефактных этапов.
- `RegistryKeys` — базовые ветки автозапуска в реестре.
- `FilesystemPaths` — базовые startup-пути в файловой системе.
- `PrefetchPath` — путь к каталогу Prefetch.
- `EventLogs` — путь к eventlog-файлам или каталогу.
- `ProcessEventIDs` — ID процессных событий.
- `NetworkEventIDs` — ID сетевых событий.
- `AmcachePath` — путь к `Amcache.hve`.
- `AmcacheKeys` — ключи `Amcache` для извлечения записей.

## Version Override Sections

Текущий `config.ini` использует такие override-секции:

- `[Windows11]`: `RegistryKeys`, `NetworkEventIDs`
- `[Windows10]`: `RegistryKeys`, `FilesystemPaths`, `NetworkEventIDs`
- `[Windows8]`: `RegistryKeys`
- `[Windows7]`: `ProcessEventIDs`, `NetworkEventIDs`, `RecentFileCachePath`
- `[WindowsVista]`: `ProcessEventIDs`, `NetworkEventIDs`, `AmcachePath`, `AmcacheKeys`
- `[WindowsXP]`: `RegistryPath`, `FilesystemPaths`, `PrefetchPath`, `EventLogs`, `ProcessEventIDs`, `NetworkEventIDs`, `AmcachePath`, `AmcacheKeys`
- `[WindowsServer]`: `RegistryKeys`

## Practical Profiles

### Fast Baseline

- `EnableParallelStages = true`
- `EnableUnallocated = false` (если нет отдельного unallocated image)

### Maximum Coverage

- Включайте источники в `Recovery` и version overrides для legacy-образов.
- При необходимости расширяйте `NetworkEventIDs` и startup-пути.

### Fast Iteration

- Сократите список `Versions` до реально ожидаемых.
- Используйте только нужные override-секции.

## Common Mistakes

- Неверный или пустой `General.Versions`.
- Неправильный путь к hive (`SOFTWARE`, `SYSTEM`, `Amcache.hve`).
- Удаление нужного ключа из `VersionDefaults` без замены в `[WindowsXX]`.

## Note

Если нужно расширить конфиг дополнительными низкоуровневыми ключами, добавляйте их только под конкретный сценарий анализа, чтобы не возвращать «раздутый» профиль.
