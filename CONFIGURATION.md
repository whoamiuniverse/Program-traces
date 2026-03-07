# Configuration

Краткий справочник по архитектуре, секциям `config.ini` и расширению поддержки Windows-версий.

## Архитектура

```text
src/
  main.cpp
  analysis/
    os/                                  # определение версии/типа Windows
    artifacts/
      orchestrator/                      # WindowsDiskAnalyzer + pipeline stages
      autorun/ amcache/ prefetch/
      event_logs/ execution/ recovery/
  parsers/                               # registry/prefetch/evt/evtx
  infra/                                 # config/logging/csv export
  errors/                                # типизированные исключения
  common/                                # string/time/number utils
```

Ключевой orchestration-слой:
- `orchestrator/windows_disk_analyzer.cpp` — 7-этапный pipeline анализа.
- `orchestrator/windows_disk_analyzer_os.cpp` — выбор тома и OS detection.
- `orchestrator/windows_disk_analyzer_config.cpp` — чтение `[Logging]`, `[Performance]`, `[CSVExport]`, `[TamperRules]`.
- `orchestrator/windows_disk_analyzer_helpers.*` — FS/mount/registry helper API.

## Секции config.ini

Основные:
- `[General]`: `Versions`.
- `[Logging]`: `DebugOSDetection`, `DebugAutorun`, `DebugPrefetch`, `DebugEventLog`, `DebugAmcache`, `DebugExecution`, `DebugRecovery`.
- `[Performance]`: `EnableParallelStages`, `WorkerThreads`, `MaxIOWorkers`, `EnableParallelPrefetch`, `EnableParallelEventLog`, `EnableParallelUserHives`.
- `[CSVExport]`: фильтры и лимиты экспортируемых метрик.
- `[TamperRules]`: правила `TamperFlags`.
- `[OSInfoRegistryPaths]`, `[OSInfoSystemRegistryPaths]`: пути к `SOFTWARE`/`SYSTEM` hive (по версии + `Default`).
- `[BuildMappingsClient]`, `[BuildMappingsServer]`: пороговые build-мэппинги.
- `[VersionDefaults]` + `[WindowsXX]`: артефактные пути/ключи по версиям.
- `[ExecutionArtifacts]`: доп. источники исполнения (ShimCache/UserAssist/RunMRU/BAM/DAM/JumpLists/SRUM/WindowsSearch/…).
- `[Recovery]`: USN/VSS/Hiber/NTFS metadata/Registry logs/Pagefile/Memory/Unallocated и native/fallback режимы.

Логирование:
- `info/warn/error` должны оставаться короткими и операционными.
- детальные причины и технический контекст выводятся в `debug` по соответствующим флагам `[Logging]`.

## Recovery расширения

Ключевые параметры `[Recovery]` для углубленного восстановления:
- Hiber: `EnableHiber`, `EnableNativeHiberParser`, `HiberFallbackToBinary`, `HiberMaxPages`, `HiberPath`.
- NTFS metadata: `EnableNTFSMetadata`, `EnableNativeFsntfsParser`, `FsntfsFallbackToBinaryOnNativeFailure`, `MFTPath`, `MFTRecordSize`, `MFTMaxRecords`, `BitmapPath`.
- Registry logs: `EnableRegistryLogsRecovery`, `RegistryConfigPath`.
- VSS snapshot replay: `EnableVSSSnapshotReplay`, `VSSSnapshotReplayMaxFiles`.

Recovery binary-scan теперь добавляет сигнатурный контекст:
- `method=string_carving|pe_signature`
- `offset=0x...`
- `entropy=...` (для PE-сигнатур)
- `chunk=...` (источник/позиция чанка).

## Добавление новой версии Windows

1. Добавьте идентификатор в `[General] -> Versions`.
2. При нестандартных hive-путях добавьте ключи в:
   - `[OSInfoRegistryPaths]`
   - `[OSInfoSystemRegistryPaths]`
3. Добавьте/обновите пороги в `[BuildMappingsClient]` или `[BuildMappingsServer]`.
4. Создайте секцию `[WindowsXX]` только с отличиями от `[VersionDefaults]`.
5. Проверьте запуск и строку в логах: `Версия Windows определена: ...`.

## Исключения

Базовый тип: `src/errors/app_exception.hpp` (`AppException`).

Оркестратор (`src/errors/disk_analyzer_exception.hpp`):
- `DiskAnalyzerException`
- `InvalidDiskRootException`
- `DiskNotMountedException`
- `RegistryHiveValidationException`
- `WindowsVolumeSelectionException`
- `OutputDirectoryException`

Модульные исключения (`config/parsing/prefetch/registry/os/csv/logger`) также наследуются от `AppException`.

## Doxygen

```bash
sudo apt update && sudo apt install doxygen -y
doxygen docs/Doxyfile
```
