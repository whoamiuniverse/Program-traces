# Program traces

Инструмент для forensic-анализа следов запуска ПО на смонтированном Windows-диске из macOS/Linux.

Подробная конфигурация: [CONFIGURATION.md](CONFIGURATION.md).

## Быстрый старт

Сборка:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Запуск:

```bash
./build/program_traces <корень_диска|auto> <config.ini> <output.csv>
./build/program_traces <config.ini> <output.csv>
./build/program_traces --log ./logs/app.log <config.ini> <output.csv>
```

Примеры:

```bash
./build/program_traces /Volumes/Untitled/ ./config.ini ~/Desktop/result.csv
./build/program_traces ./config.ini ~/Desktop/result.csv
./build/program_traces --log ./logs/program-traces.log ./config.ini ~/Desktop/result.csv
```

Справка:

```bash
./build/program_traces --help
./build/program_traces --version
```

Ожидаемый консольный вывод:

```text
=== Запуск анализа диска Windows ===
        Корневая директория: /Volumes/Untitled
        Конфигурационный файл: ./config.ini
        Выходной CSV-файл: /tmp/out.csv

=== Анализ успешно завершен ===
Результаты сохранены в: /tmp/out.csv
```

## Пайплайн

`WindowsDiskAnalyzer` выполняет 7 этапов:

1. Autorun
2. Amcache / RecentFileCache.bcf
3. Prefetch
4. EventLog / Security context
5. Execution artifacts (ShimCache, BAM/DAM, Jump Lists, LNK, Task Scheduler, SRUM, Windows Search и др.)
6. Recovery (USN, VSS, Hiber, NTFS metadata, Registry logs)
7. CSV export

## Формат результата

Основной CSV содержит агрегированные столбцы:

- `ИсполняемыйФайл`
- `Пути`
- `Версии`
- `Хэши`
- `РазмерФайла`
- `ВременаЗапуска`
- `FirstSeenUTC`
- `LastSeenUTC`
- `TimelineArtifacts`
- `RecoveredFrom`
- `Users`, `UserSIDs`, `LogonIDs`, `LogonTypes`
- `ElevationType`, `ElevatedToken`, `IntegrityLevel`, `Privileges`
- `Автозагрузка`
- `СледыУдаления`
- `КоличествоЗапусков`
- `Тома(серийный:тип)`
- `СетевыеПодключения`
- `NetworkTimelineArtifacts`
- `NetworkContextSources`
- `NetworkProfiles`
- `FirewallRules`
- `ФайловыеМетрики`
- `EvidenceSources`
- `TamperFlags`

Recovery-данные дополнительно выгружаются в отдельный файл `<base>_recovery.csv` со столбцами:

```text
ExecutablePath;Source;RecoveredFrom;Timestamp;Details;TamperFlag
```

## Коды выхода

- `0` — успешное завершение
- `1` — ошибка аргументов командной строки
- `2` — ошибка файловой системы
- `3` — ошибка анализа (парсинг / конфиг / ОС)
- `4` — ошибка экспорта CSV

## Тесты

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DPROGRAM_TRACES_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

В проекте есть unit-тесты для `ConfigUtils`, `time_utils`, `CSVExporter`, `Amcache` fallback, `ShimCache` decoder, `LNK` parser и CLI smoke-проверка.

## Linux

Под Linux проект ожидает prebuilt-статические библиотеки в `libs/linux/`.

Автоматическая сборка зависимостей:

```bash
bash scripts/build_deps_linux.sh
```

Только обязательный набор зависимостей:

```bash
bash scripts/build_deps_linux.sh --required-only
```

После этого:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

Для воспроизводимой сборки есть `Dockerfile` на базе Ubuntu 22.04:

```bash
docker build -t program-traces .
```

## Зависимости

Обязательные prebuilt-библиотеки:

- `libregf`
- `libscca`
- `libevtx`
- `libevt`
- `libspdlog`

Опциональные:

- `libesedb`
- `libfusn`
- `libvshadow`
- `libhibr`
- `libfsntfs`

## Ограничения

- Интеграционные тесты Win7/Win10 ожидают реальные fixture-образы и сейчас помечаются `SKIP`, если они отсутствуют.
- Разбор `automaticDestinations-ms` выполняется через минимальный OLE2 reader; при ошибке сохраняется binary fallback.
- `customDestinations-ms` разбираются через поиск встроенных LNK-блоков; это менее полно, чем отдельный format-aware parser.
- Поддержка Windows ARM64 отдельно не валидировалась.
- Для legacy `.evt` артефактов Windows XP полнота зависит от состояния классических журналов на образе.
- `libfsntfs` native parsing для `$MFT` пока не включен как полноценный production parser; используется fallback-режим с tamper-эвристикой `mft_si_fn_divergence`.
