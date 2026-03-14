# Program traces

Инструмент для forensic-анализа следов запуска ПО на смонтированном Windows-диске из macOS/Linux.

Подробная конфигурация: [CONFIGURATION.md](CONFIGURATION.md).

`config.ini` в репозитории намеренно упрощен: в нем оставлены базовые, часто
используемые параметры. Полный список опциональных ключей и расширенных
override-настроек описан в `CONFIGURATION.md`.

В самом `config.ini` добавлены короткие комментарии по каждому полю.

## Быстрый старт

Сборка:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

По умолчанию unit-тесты не собираются, поэтому обычная конфигурация не требует `GTest` и не пытается скачивать его из сети.

Настройка перед запуском:

1. При необходимости скорректируйте `Versions` в `config.ini`.
2. Проверьте базовые секции текущего профиля: `[Performance]`, `[Recovery]`, `[VersionDefaults]`.
3. Для сложных образов (legacy/нестандартные пути) используйте version-overrides (`[WindowsXX]`) и расширенные ключи по `CONFIGURATION.md`.

Ключевые поля минимального `config.ini`:

- `General.Versions` — порядок определения версии ОС.
- `Performance.EnableParallelStages` — общий флаг параллельного выполнения.
- `Recovery.EnableUnallocated` — сканировать ли unallocated image.
- `VersionDefaults.*` — базовые пути/ID для анализаторов (автозагрузка, prefetch, eventlog, amcache).

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

Тестовая сборка включается отдельно:

```bash
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug -DPROGRAM_TRACES_BUILD_TESTS=ON
cmake --build build-tests -j
ctest --test-dir build-tests --output-on-failure
```

В проекте есть unit-тесты для `ConfigUtils`, `time_utils`, `CSVExporter`, `OSDetection`, `RegistryParser`, `PrefetchParser`, `Amcache` fallback, `ShimCache` decoder, `LNK` parser и CLI smoke-проверка.

Если `GTest` уже установлен в системе и доступен для `find_package(GTest)`, конфигурации выше достаточно.
Если локального `GTest` нет, разрешите явную загрузку зависимостей для тестов:

```bash
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DPROGRAM_TRACES_BUILD_TESTS=ON \
  -DPROGRAM_TRACES_FETCH_GTEST=ON
cmake --build build-tests -j
ctest --test-dir build-tests --output-on-failure
```

Если включить `PROGRAM_TRACES_BUILD_TESTS=ON` без установленного `GTest` и без `PROGRAM_TRACES_FETCH_GTEST=ON`, CMake пропустит таргет `program_traces_tests` и выведет предупреждение.

## Зависимости и установка

Проект ожидает prebuilt-статические библиотеки в `libs/<platform>/`, где `<platform>` — `linux` или `macos`.

Для подготовки окружения и сборки зависимостей используйте единый cross-platform script:

```bash
bash scripts/install_deps.sh
```

Если нужно, чтобы скрипт сам поставил системные пакеты:

```bash
bash scripts/install_deps.sh --install-system-deps
```

Только обязательный набор библиотек:

```bash
bash scripts/install_deps.sh --required-only
```

Сценарий выполняет этапы последовательно:

1. определяет платформу и выбирает `libs/linux/` или `libs/macos/`;
2. при флаге `--install-system-deps` ставит системные build-зависимости для Linux/macOS;
3. клонирует или обновляет исходники libyal/spdlog;
4. собирает обязательные библиотеки;
5. при необходимости собирает опциональные библиотеки и раскладывает `.a`/`include` в ожидаемую структуру.

После этого:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
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
