# Optimization Plan (Speed-First)

## Goal

Ускорить end-to-end анализ диска за счет параллелизма, overlap I/O и CPU, снижения lock contention и сокращения лишних копирований данных. Приоритет: **время выполнения**, а не размер кода.

## 0. Baseline And Profiling

1. Зафиксировать базовый набор сценариев:
- Небольшой образ (быстрый smoke).
- Средний пользовательский диск.
- Тяжелый корпоративный диск.
2. Замерять:
- Total wall-clock time.
- Время по этапам: `autorun`, `prefetch`, `eventlog`, `amcache`, `execution`, `recovery`, `csv export`.
- CPU utilization, peak RSS, disk read throughput.
3. Ввести метрики в лог:
- `stage_duration_ms`
- `processed_items_count`
- `errors_count`
- `worker_threads_used`

## 1. Pipeline Decomposition

Разделить обработку на независимые стадии и запускать их как задачи:

1. Stage A: обнаружение ОС + подготовка конфигурации.
2. Stage B: независимые сборщики артефактов.
3. Stage C: merge/normalization.
4. Stage D: tamper rules + recovery merge.
5. Stage E: CSV export.

Правило: merge-фазы оставить детерминированными и последовательными, сбор данных распараллелить.

## 2. Concurrency Model (std-only)

Использовать гибрид:

1. Межэтапный параллелизм через `std::async(std::launch::async, ...)`.
2. Внутри тяжелых этапов:
- фиксированный пул `std::thread`,
- очередь задач + `std::mutex` + `std::condition_variable`,
- завершение через `std::future`/`std::promise` или флаг остановки + `join`.
3. Для коротких задач: пакетный `std::async` с ограничением количества одновременно активных future.

## 3. Stage-Level Parallelization

## 3.1 EventLog

1. Разбить список лог-файлов на чанки.
2. Каждый worker парсит свой чанк и пишет в локальные структуры.
3. После `future.get()` делать единый merge в общий `process_data`.

Ограничение: max workers = `min(hardware_concurrency, configured_limit, number_of_logs)`.

## 3.2 Execution Evidence

1. Группы collectors (`software/system/filesystem/database`) запускать параллельно.
2. Внутри user-hive collectors использовать параллельный проход по SID-хайвам.
3. Для каждого collector:
- локальный буфер результатов,
- финальный merge в одной точке.

## 3.3 Recovery

1. `USN`, `VSS`, `Hiber`, `RegistryLog`, `NTFS metadata` запускать независимыми задачами.
2. Нормализовать в общий формат `RecoveryEvidence` и затем merge.

## 4. Data Contention And Memory

1. Избегать записи в общий `unordered_map` из нескольких потоков.
2. Strategy:
- thread-local map/vector,
- post-merge reduction.
3. Снизить realloc:
- `reserve()` для ожидаемых размеров коллекций.
4. Минимизировать копирования:
- move semantics при переносе промежуточных результатов.

## 5. I/O Optimization

1. Батчировать чтение директорий и файлов, не делать повторных `exists`/`status` без нужды.
2. Кэшировать результат case-insensitive path resolution.
3. Для крупных логов/баз:
- читать блоками,
- парсить по streaming-схеме, где возможно.
4. Ограничить одновременные I/O workers отдельным лимитом (`max_io_workers`), чтобы не перегружать диск.

## 6. Error Isolation In Parallel Execution

1. Каждая асинхронная задача возвращает `Result<T, Error>`-подобную структуру.
2. Ошибки задач не валят весь процесс немедленно, если артефакт не критичный.
3. Критичные ошибки (невалидный root/config) завершают выполнение быстро (fail-fast).

## 7. Determinism And Reproducibility

1. После параллельного сбора сортировать ключевые списки перед экспортом.
2. Объединение данных делать в фиксированном порядке этапов.
3. Логи маркировать `task_id` и `stage_name` для трассировки.

## 8. Configuration Knobs

Добавить/использовать параметры в `config.ini`:

1. `EnableParallelStages`
2. `EnableParallelEventLog`
3. `EnableParallelExecutionGroups`
4. `EnableParallelUserHiveAnalysis`
5. `WorkerThreads`
6. `MaxIoWorkers`
7. `TaskQueueCapacity`

Рекомендация по умолчанию:
- `WorkerThreads = hardware_concurrency()`
- `MaxIoWorkers = min(4, WorkerThreads)`

## 9. Validation And Performance Gates

1. Добавить performance regression test (smoke benchmark) в CI (допуск, например +15% к baseline).
2. Проверять корректность результата при 1 потоке и N потоках (сравнение CSV semantic equality).
3. Отдельный стресс-тест на гонки:
- большой набор event logs,
- много user hives,
- конкурентный merge.

## 10. Implementation Order (Practical)

1. Ввести stage timers и метрики.
2. Параллелизовать EventLog (самый дорогой I/O+CPU этап).
3. Параллелизовать ExecutionEvidence groups.
4. Параллелизовать Recovery analyzers.
5. Перевести merge на thread-local + reduction.
6. Тонкая настройка ограничений потоков по реальным замерам.

## Expected Result

При корректной реализации и отсутствии I/O bottleneck на носителе ожидается ускорение:
- x1.5-x2.5 на средних дисках,
- до x3 на сценариях с большим количеством EVTX/артефактов и достаточным числом CPU-ядер.
