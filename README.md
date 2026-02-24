# Program traces

## Обзор

Приложение извлекает следы запуска программ из Windows на подключённом диске.

## Архитектура

Исходный код организован в каталоге `src/`:

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

Направление зависимостей:
- `main.cpp -> analysis`
- `analysis -> parsers + infra + errors + common`
- `parsers -> errors + common`
- `infra` и `common` переиспользуемые и не должны зависеть от `analysis`

## Документация

Для генерации документации:

1. Установите doxygen:

```bash
sudo apt update && sudo apt install doxygen -y
```

2. Сгенерируйте документацию:

```bash
doxygen docs/Doxyfile
```

## Зависимости

### Установка базовых зависимостей

```bash
sudo apt update && sudo apt install autopoint cmake libspdlog-dev git autoconf automake libtool pkg-config gcc g++ make libfuse-dev -y
```

### Установка libregf

1. Клонируйте репозиторий:

```bash
git clone https://github.com/libyal/libregf.git
cd libregf
```

2. Соберите и установите библиотеку:

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Обновите кэш библиотек:

```bash
sudo ldconfig && cd ..
```

4. Проверьте установку:

```bash
regfinfo
```

### Установка libscca

1. Клонируйте репозиторий:

```bash
git clone https://github.com/libyal/libscca.git
cd libscca
```

2. Соберите и установите библиотеку:

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Обновите кэш библиотек:

```bash
sudo ldconfig && cd ..
```

4. Проверьте установку:

```bash
sccainfo
```

### Установка libevtx

1. Клонируйте репозиторий:

```bash
git clone https://github.com/libyal/libevtx.git
cd libevtx
```

2. Соберите и установите библиотеку:

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Обновите кэш библиотек:

```bash
sudo ldconfig && cd ..
```

4. Проверьте установку:

```bash
evtxexport --version
```

### Установка libevt

1. Клонируйте репозиторий:

```bash
git clone https://github.com/libyal/libevt
cd libevt
```

2. Соберите и установите библиотеку:

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Обновите кэш библиотек:

```bash
sudo ldconfig && cd ..
```

4. Проверьте установку:

```bash
evtexport --version
```

## Сборка

Из корня репозитория:

```bash
mkdir -p build && cd build
cmake ..
cmake --build .
```

## Запуск

После сборки запуск:

```bash
./program_traces
```

## Добавление Новой Версии Windows

Простой чеклист:

1. Добавьте имя версии в `[General] -> Versions` в [config.ini](config.ini).
2. Если для новой версии путь к `SOFTWARE` отличается от типового, добавьте override в `[OSInfoRegistryPaths]` (`<Version> = <path>`).
3. Если нужны особые артефактные параметры, создайте секцию `[<Version>]` и укажите только отличия от `[VersionDefaults]`:
   - `RegistryPath`, `RegistryKeys`, `FilesystemPaths`
   - `PrefetchPath`, `EventLogs`, `ProcessEventIDs`, `NetworkEventIDs`
   - `AmcachePath`, `AmcacheKeys`
4. При необходимости уточните сопоставление build-номеров в `[BuildMappingsClient]` или `[BuildMappingsServer]`.
5. Запустите анализ и проверьте, что в логах появилась корректная строка определения ОС (`Версия Windows определена: ...`).

Минимальный пример добавления:

```ini
[General]
Versions = WindowsXP,WindowsVista,Windows7,Windows8,Windows10,Windows11,WindowsServer,Windows12

[Windows12]
NetworkEventIDs = 5156,5157,3
```
