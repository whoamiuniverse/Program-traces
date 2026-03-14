# Testing

## Overview

Тесты собираются отдельно от основного релизного бинаря.

В проекте есть unit-тесты для конфигурации, парсеров, CSV-экспорта, OS detection и CLI smoke.

## Build And Run

```bash
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug -DPROGRAM_TRACES_BUILD_TESTS=ON
cmake --build build-tests -j
ctest --test-dir build-tests --output-on-failure
```

## GTest

Если `GTest` установлен и находится через `find_package(GTest)`, этого достаточно.

Если `GTest` не установлен локально:

```bash
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DPROGRAM_TRACES_BUILD_TESTS=ON \
  -DPROGRAM_TRACES_FETCH_GTEST=ON
cmake --build build-tests -j
ctest --test-dir build-tests --output-on-failure
```

Если включить `PROGRAM_TRACES_BUILD_TESTS=ON` без локального `GTest` и без `PROGRAM_TRACES_FETCH_GTEST=ON`, CMake пропустит target `program_traces_tests`.
