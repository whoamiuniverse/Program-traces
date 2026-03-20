# Dependencies

## Overview

Зависимости собираются локально в `libs/<platform>`, где `<platform>` — `linux` или `macos`.

Скрипт проверяет обязательные build-tools и, если чего-то не хватает,
предлагает установить недостающие пакеты через доступный пакетный менеджер.

## Main Script

```bash
bash scripts/install_deps.sh
```

## Common Commands

```bash
# Полная сборка зависимостей
bash scripts/install_deps.sh

# Только обязательные библиотеки
bash scripts/install_deps.sh --required-only

# Очистить временную директорию перед сборкой
bash scripts/install_deps.sh --clean

# Собрать и затем обязательно удалить артефакты
bash scripts/install_deps.sh --cleanup-after

# Только очистка (без сборки)
bash scripts/install_deps.sh --cleanup-only
```

## Script Options

- `--required-only` — собирать только обязательные библиотеки.
- `--clean` — удалить `.deps-build/<platform>` перед стартом.
- `--cleanup-after` — удалить собранные/скачанные артефакты после завершения.
- `--cleanup-only` — выполнить только cleanup без сборки.

## Required Libraries

- `libregf`
- `libscca`
- `libevtx`
- `libevt`
- `libspdlog`

## Optional Libraries

- `libesedb`
- `libfusn`
- `libvshadow`
- `libhibr`
- `libfsntfs`
