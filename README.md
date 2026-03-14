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
```

Примеры:

```bash
./build/program_traces /Volumes/Untitled/ ./config.ini ~/Desktop/result.csv
./build/program_traces ./config.ini ~/Desktop/result.csv
```

## CLI

```bash
./build/program_traces --help
./build/program_traces --version
```

## Output

Основной результат: CSV-файл с агрегированными следами запуска программ.  
Дополнительно: `<output_base>_recovery.csv` с recovery-находками (если включены соответствующие источники).
