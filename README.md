# Program traces

Инструмент для forensic-анализа артефактов запуска ПО на смонтированном Windows-диске (macOS/Linux).

Подробная архитектура и настройка `config.ini`: [CONFIGURATION.md](CONFIGURATION.md).

## Зависимости

Проект ожидает prebuilt-статические библиотеки в `libs/<platform>/`:
- `libregf`
- `libscca`
- `libevtx`
- `libevt`
- `libspdlog`
- `libfmt`
- опционально: `libesedb`, `libfusn`, `libvshadow`

Если prebuilt отсутствуют, соберите зависимости вручную (по шаблону libyal):

```bash
git clone https://github.com/libyal/<repo>.git
cd <repo>
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
```

## Сборка

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Запуск

```bash
./build/program_traces <корень_диска|auto> <config.ini> <output.csv>
./build/program_traces <config.ini> <output.csv>
```

Примеры:

```bash
./build/program_traces /Volumes/Untitled/ ./config.ini ~/Desktop/result.csv
./build/program_traces ./config.ini ~/Desktop/result.csv
```

## Что делает пайплайн

`WindowsDiskAnalyzer` выполняет 7 этапов (с логированием прогресса):
1. Autorun
2. Amcache
3. Prefetch
4. EventLog
5. Execution artifacts (ShimCache/UserAssist/RunMRU/BAM/DAM/JumpLists/SRUM/…)
6. Recovery (USN/VSS/Pagefile/Memory/Unallocated)
7. CSV export

## Логирование и исключения

- `info/warn/error`: короткие сообщения по этапам и итогам.
- подробная диагностика включается через debug-флаги в `[Logging]` (`config.ini`).
- ошибки приложения типизированы (иерархия от `AppException`), для оркестратора используются `DiskAnalyzerException` и наследники.
