# Program traces

## Overview

Инструмент для forensic-анализа следов запуска программ на смонтированном Windows-диске из macOS/Linux.

## Documentation

- Конфигурация: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- Сборка зависимостей: [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)
- Тесты: [docs/TESTING.md](docs/TESTING.md)

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run

```bash
./build/program_traces <disk_root|auto> <config.ini> <output.csv>
./build/program_traces --log ./logs/program-traces.log <config.ini> <output.csv>
./build/program_traces -d auto -c ./config.ini -o ~/Desktop/result.csv
./build/program_traces -c ./config.ini -o ~/Desktop/result.csv --recovery-csv
./build/program_traces -c ./config.ini -o ~/Desktop/result.csv --recovery-output ~/Desktop/recovery.csv
```

Примеры:

```bash
./build/program_traces /Volumes/Untitled/ ./config.ini ~/Desktop/result.csv
./build/program_traces ./config.ini ~/Desktop/result.csv
./build/program_traces --disk-root /Volumes/Untitled --config ./config.ini --output ~/Desktop/result.csv
```

## CLI

```bash
./build/program_traces --help
./build/program_traces --version
```

## Output

Основной результат: CSV-файл с агрегированными следами запуска программ.  
Recovery-CSV создается только по запросу пользователя:
- `--recovery-csv` -> `<output_base>_recovery.csv`
- `--recovery-output <path>` -> в указанный путь
