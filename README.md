# Program traces

Инструмент для анализа артефактов запуска программ на подключенном Windows-диске.

Архитектура и настройка `config.ini`: [CONFIGURATION.md](CONFIGURATION.md).

## Зависимости

Проект по умолчанию использует prebuilt-библиотеки из `libs/<platform>/`.
Если prebuilt отсутствуют, соберите зависимости вручную.

### Быстрая установка базовых пакетов (Linux)

```bash
sudo apt update && sudo apt install autopoint cmake git autoconf automake libtool pkg-config gcc g++ make libfuse-dev -y
```

### Сборка зависимостей вручную

Универсальный шаблон:

```bash
git clone https://github.com/libyal/<repo>.git
cd <repo>
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
cd ..
```

Нужные репозитории:
- `libregf` (проверка: `regfinfo`)
- `libscca` (проверка: `sccainfo`)
- `libevtx` (проверка: `evtxexport --version`)
- `libevt` (проверка: `evtexport --version`)

## Сборка

Из корня репозитория:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Запуск

Формат:

```bash
./build/program_traces <корень_диска|auto> <config.ini> <output.csv>
./build/program_traces <config.ini> <output.csv>
```

Примеры:

```bash
./build/program_traces /Volumes/Untitled/ config.ini ~/Desktop/result.csv
./build/program_traces config.ini ~/Desktop/result.csv
```
