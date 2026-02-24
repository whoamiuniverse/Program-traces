Program traces
====================================

## Overview

The program extracts traces of software startup
from the Windows operating system

## Architecture

Source code is organized under `src/`:

```text
src/
  main.cpp                     # entrypoint
  analysis/                    # сценарии анализа диска
    os/                        # определение версии/типа Windows
    artifacts/                 # анализ артефактов запуска ПО
  parsers/                     # format adapters (registry, prefetch, evt/evtx)
  errors/                      # типы исключений
  infra/                       # config, logging, export
  common/                      # shared helpers (string/time/parse)
```

Dependency direction:
- `main.cpp -> analysis`
- `analysis -> parsers + infra + errors + common`
- `parsers -> errors + common`
- `infra` and `common` are reusable and should not depend on `analysis`

## Documentation

To create the documentation, follow these steps:

1. Install doxygen

```bash
sudo apt update && sudo apt install doxygen -y
```

2. Generate the documentation

```bash
doxygen docs/Doxyfile
```

## Dependencies

### Installing common dependencies

```bash
sudo apt update && sudo apt install autopoint cmake libspdlog-dev git autoconf automake libtool pkg-config gcc g++ make libfuse-dev -y
```

### Install libregf

1. Clone the repository

```bash
git clone https://github.com/libyal/libregf.git
cd libregf
```

2. Build and install the library "libregf"

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Update the library cache

```bash
sudo ldconfig && cd ..
```

4. Checking the installation

```bash
regfinfo
```

### Install libscca

1. Clone the repository

```bash
git clone https://github.com/libyal/libscca.git
cd libscca
```

2. Build and install the library "libregf"

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Update the library cache

```bash
sudo ldconfig && cd ..
```

4. Checking the installation

```bash
sccainfo
```

### Install libevtx

1. Clone the repository libevtx

```bash
git clone https://github.com/libyal/libevtx.git
cd libevtx
```

2. Build and install the library "libevtx"

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Update the library cache

```bash
sudo ldconfig && cd ..
```

4. Checking the installation

```bash
evtxexport --version
```

### Install libevt

1. Clone the repository libevt

```bash
git clone https://github.com/libyal/libevt
cd libevt
```

2. Build and install the library "libevt"

```bash
./synclibs.sh
./autogen.sh
./configure
make
sudo make install
```

3. Update the library cache

```bash
sudo ldconfig && cd ..
```

4. Checking the installation

```bash
evtexport --version
```

## Build

From the root of the repository:

```bash
mkdir build && cd build
```

```bash
cmake ..
```

```bash
cmake --build .
```
