# Configuration

Подробный справочник по настройке `config.ini` для `Program traces`.

## 1. Как работает конфиг

### 1.1 Fallback-логика

Проект использует два уровня настроек:

1. Глобальные секции (`[General]`, `[Performance]`, `[Recovery]`, `[ExecutionArtifacts]` и т.д.).
2. Версионные секции (`[Windows11]`, `[Windows7]`, `[WindowsXP]`, ...).

Для version-aware ключей применяется fallback:

1. Сначала читается значение из секции конкретной версии (например, `[Windows10]`).
2. Если ключ отсутствует/пустой, берется значение из `[VersionDefaults]`.

### 1.2 Что обязательно должно быть

Минимально обязательные элементы:

- `[General]` с ключом `Versions`.
- Базовые OS-detection секции:
  - `[OSInfoRegistryPaths]` (минимум `Default`)
  - `[OSInfoHive]` (минимум `Default`)
  - `[OSInfoKeys]` (минимум `Default`)
- `[VersionDefaults]` с базовыми путями/ID для артефактов.

Остальные секции опциональны: если ключи отсутствуют, используются кодовые значения по умолчанию.

## 2. Пошаговая настройка `config.ini`

1. Скопируйте `config.ini` из репозитория как базовый профиль.
2. Настройте список версий в `[General]/Versions` в нужном порядке.
3. Проверьте `[VersionDefaults]`:
   - пути к registry hive и Prefetch;
   - paths автозагрузки;
   - EventLog-пути и IDs.
4. Добавьте/оставьте только нужные version-overrides (`[Windows11]`, `[WindowsXP]` и т.п.).
5. Настройте производительность (`[Performance]`) под машину и объем образа.
6. При необходимости включайте/выключайте источники в `[Recovery]` и `[ExecutionArtifacts]`.
7. Проверьте запуск:
   - `./build/program_traces --help`
   - `./build/program_traces <disk_root|auto> ./config.ini /tmp/out.csv`

## 3. Поля текущего `config.ini` (минимальный профиль)

Ниже перечислены поля, которые **сейчас реально присутствуют** в `config.ini`.

### [General]

- `Versions` — порядок проверки версий Windows в детекторе ОС.

### [Logging]

- `DebugEventLog` — включает/выключает DEBUG-логи этапа EventLog.

### [Performance]

- `EnableParallelStages` — разрешает параллельный запуск независимых этапов.

### [OSInfoRegistryPaths]

- `Default` — базовый путь к `SOFTWARE` hive.
- `WindowsXP` — override пути к `SOFTWARE` hive для XP.
- `WindowsServer` — override пути к `SOFTWARE` hive для server-линейки.

### [OSInfoSystemRegistryPaths]

- `Default` — базовый путь к `SYSTEM` hive.
- `WindowsXP` — override пути к `SYSTEM` hive для XP.
- `WindowsServer` — override пути к `SYSTEM` hive для server-линейки.

### [OSInfoHive]

- `Default` — ключ в `SOFTWARE` hive, откуда читаются данные версии ОС.

### [OSInfoKeys]

- `Default` — список значений из `CurrentVersion`, используемых в OS detection.

### [BuildMappingsClient]

- `<build> = <name>` — маппинг build-номера на клиентское имя ОС.

### [BuildMappingsServer]

- `<build> = <name>` — маппинг build-номера на серверное имя ОС.

### [OSKeywords]

- `DefaultServerKeywords` — fallback-слова для определения server edition.

### [Recovery]

- `EnableUnallocated` — включает/выключает сканирование unallocated image.

### [VersionDefaults]

- `RegistryPath` — базовый путь к `SOFTWARE` hive для артефактных этапов.
- `RegistryKeys` — базовые ветки автозапуска в реестре.
- `FilesystemPaths` — базовые startup-пути в файловой системе.
- `PrefetchPath` — путь к каталогу Prefetch.
- `EventLogs` — путь к файлам/каталогу EventLog.
- `ProcessEventIDs` — ID событий процессов для EventLog-корреляции.
- `NetworkEventIDs` — ID сетевых событий.
- `AmcachePath` — путь к `Amcache.hve`.
- `AmcacheKeys` — ключи `Amcache` для извлечения записей.

### Version Overrides

Используются только для отличий от `[VersionDefaults]`:

- `[Windows11]`: `RegistryKeys`, `NetworkEventIDs`
- `[Windows10]`: `RegistryKeys`, `FilesystemPaths`, `NetworkEventIDs`
- `[Windows8]`: `RegistryKeys`
- `[Windows7]`: `ProcessEventIDs`, `NetworkEventIDs`, `RecentFileCachePath`
- `[WindowsVista]`: `ProcessEventIDs`, `NetworkEventIDs`, `AmcachePath`, `AmcacheKeys`
- `[WindowsXP]`: `RegistryPath`, `FilesystemPaths`, `PrefetchPath`, `EventLogs`, `ProcessEventIDs`, `NetworkEventIDs`, `AmcachePath`, `AmcacheKeys`
- `[WindowsServer]`: `RegistryKeys`

## 4. Секции и ключи

### [General]

- `Versions` (обязательный): список секций ОС в порядке проверки, через запятую.

Пример:

```ini
[General]
Versions = WindowsXP, WindowsVista, Windows7, Windows8, Windows10, Windows11, WindowsServer
```

### [Logging]

Флаги этапов для DEBUG-логов:

- `DebugOSDetection` (default: `true`)
- `DebugAutorun` (default: `true`)
- `DebugPrefetch` (default: `true`)
- `DebugEventLog` (default: `true`)
- `DebugAmcache` (default: `true`)
- `DebugExecution` (default: `true`)
- `DebugRecovery` (default: `true`)

Если секция или ключ отсутствуют, соответствующий этап использует default.

### [Performance]

Ключи:

- `EnableParallelStages` (default: `false`)  
  Общий флаг параллельного режима.
- `WorkerThreads` (default: `4`)  
  Верхний лимит worker-потоков.
- `MaxIOWorkers` (default: `4`)  
  Лимит IO-задач в оркестраторе.
- `EnableParallelPrefetch` (default: fallback на `EnableParallelStages`)
- `EnableParallelEventLog` (default: fallback на `EnableParallelStages`)
- `EnableParallelUserHives` (default: fallback на `EnableParallelStages`)

Практика:

- Для локального ноутбука: `WorkerThreads = 4`.
- Для мощной машины: `WorkerThreads = 8..16` (по нагрузке диска/CPU).

### [TamperRules]

Ключи:

- `EnablePrefetchMissingRule` (default: `true`)
- `PrefetchMissingRequireProcessImage` (default: `true`)
- `PrefetchMissingRuntimeSources`  
  Список источников, доказывающих исполнение (через запятую).
- `EnableSIFNDivergenceCheck` (default: `true`)
- `TimestampDivergenceThresholdSec` (default: `2`)

### [OSInfoRegistryPaths], [OSInfoSystemRegistryPaths], [OSInfoHive], [OSInfoKeys], [OSKeywords]

Используются детектором ОС.

- `[OSInfoRegistryPaths]`: путь к `SOFTWARE` hive (`Default` + при необходимости overrides).
- `[OSInfoSystemRegistryPaths]`: путь к `SYSTEM` hive.
- `[OSInfoHive]`: путь к разделу (обычно `Microsoft/Windows NT/CurrentVersion`).
- `[OSInfoKeys]`: список считываемых значений (`ProductName`, `CurrentBuild`, ...).
- `[OSKeywords]`: fallback-ключевые слова для server edition.

### [BuildMappingsClient] и [BuildMappingsServer]

Пороговые маппинги build-номера на семейство ОС.  
Используются для нормализации имени ОС в отчётах и при выборе version-section.

### [Recovery]

Базовые ключи (часто используются в `config.ini`):

- `EnableUSN` (default: `true`)
- `EnableVSS` (default: `true`)
- `EnableHiber` (default: `true`)
- `EnableNTFSMetadata` (default: `true`)
- `EnableRegistryLogsRecovery` (default: `true`)
- `EnableUnallocated` (default: `true`)
- `BinaryScanMaxMB` (default: `64`)
- `MaxCandidatesPerSource` (default: `2000`)

Расширенные recovery-ключи (опционально):

- USN:
  - `EnableNativeUSNParser` (default: `true`)
  - `USNFallbackToBinaryOnNativeFailure` (default: `true`)
  - `USNNativeMaxRecords` (default: `200000`)
  - `USNJournalPath` (default: empty)
  - `EnableLogFile` (default: `true`)
- VSS/pagefile/memory:
  - `EnableNativeVSSParser` (default: `true`)
  - `VSSFallbackToBinaryOnNativeFailure` (default: `true`)
  - `VSSNativeMaxStores` (default: `32`)
  - `EnableVSSSnapshotReplay` (default: `true`)
  - `VSSSnapshotReplayMaxFiles` (default: `200`)
  - `VSSVolumePath` (default: empty)
  - `EnablePagefile` (default: `true`)
  - `EnableMemory` (default: `true`)
  - `UnallocatedImagePath` (default: empty)
- Hiber:
  - `EnableNativeHiberParser` (default: `true`)
  - `HiberFallbackToBinary` (default: `true`)
  - `HiberMaxPages` (default: `16384`)
  - `HiberPath` (default: `hiberfil.sys`)
- NTFS metadata:
  - `EnableNativeFsntfsParser` (default: `true`)
  - `FsntfsFallbackToBinaryOnNativeFailure` (default: `true`)
  - `MFTPath` (default: `$MFT`)
  - `MFTMaxRecords` (default: `200000`)
  - `MFTRecordSize` (default: `1024`)
  - `BitmapPath` (default: `$Bitmap`)
- Registry logs:
  - `RegistryConfigPath` (default: `Windows/System32/config`)

### [ExecutionArtifacts]

Коллекторы execution-сигналов:

- Registry: `EnableShimCache`, `EnableUserAssist`, `EnableRunMRU`, `EnableFeatureUsage`, `EnableRecentApps`, `EnableBamDam`, `EnableServices`, `EnableNetworkProfiles`, `EnableFirewallRules`, `EnableTaskScheduler`, `EnableIFEO`, `EnableMuiCache`, `EnableAppCompatFlags`, `EnableTypedPaths`, `EnableLastVisitedMRU`, `EnableOpenSaveMRU`.
- Filesystem: `EnableHostsFile`, `EnableJumpLists`, `EnableLnkRecent`, `EnableWER`, `EnableTimeline`, `EnableBITS`, `EnableWMIRepository`, `EnablePSHistory`.
- Databases: `EnableWindowsSearch`, `EnableSRUM`.
- Tamper: `EnableSecurityLogTamperCheck`.

Ключи native/fallback и лимитов:

- `EnableNativeWindowsSearchParser` (default: `true`)
- `WindowsSearchFallbackToBinaryOnNativeFailure` (default: `true`)
- `WindowsSearchNativeMaxRecordsPerTable` (default: `25000`)
- `WindowsSearchTableAllowlist` (default: empty = все таблицы)
- `EnableNativeSRUM` (default: `true`)
- `SrumFallbackToBinaryOnNativeFailure` (default: `true`)
- `SrumNativeMaxRecordsPerTable` (default: `25000`)
- `SrumTableAllowlist` (default: empty = все таблицы)
- `BinaryScanMaxMB` (default: `64`)
- `MaxCandidatesPerSource` (default: `2000`)
- `IncludeInactiveFirewallRules` (default: `false`)

Расширенные path/key override-ключи (опционально):

- `UserAssistKey`, `RunMRUKey`
- `FeatureUsageAppSwitchedKey`, `FeatureUsageShowJumpViewKey`, `FeatureUsageAppBadgeUpdatedKey`
- `RecentAppsRootKey`, `RecentAppsRecentItemsSuffix`
- `ShimCacheValuePath`
- `MuiCacheKey`, `AppCompatLayersKey`, `AppCompatAssistKey`, `TypedPathsKey`, `LastVisitedMruKey`, `OpenSaveMruKey`
- `PSHistorySuffix`
- `BamRootPath`, `DamRootPath`, `BamLegacyRootPath`, `DamLegacyRootPath`
- `ServicesRootPath`
- `NetworkProfilesRootKey`, `NetworkSignatureRoots`, `FirewallRulesKeys`
- `RecentLnkPath`, `JumpListAutoPath`, `JumpListCustomPath`
- `TaskSchedulerPath`, `TaskCacheTasksKey`, `TaskCacheTreeKey`
- `IFEORootKey`, `IFEOWow6432RootKey`
- `WERProgramDataPath`, `WERUserPath`, `TimelineRootPath`, `BITSDownloaderPath`
- `HostsFilePath`, `WMIRepositoryPath`, `WindowsSearchPath`, `SRUMPath`
- `SecurityLogPath`

### [SecurityContext]

Корреляция security-событий с процессами:

- `Enabled` (default: `true`)
- `SecurityLogPath` (default: `Windows/System32/winevt/Logs/Security.evtx`)
- `ProcessCreateEventIDs` (default: `4688`)
- `LogonEventIDs` (default: `4624`)
- `PrivilegeEventIDs` (default: `4672`)
- `LogonCorrelationWindowSeconds` (default: `43200`)
- `PidCorrelationWindowSeconds` (default: `3600`)

Если `SecurityLogPath` не указан в `[SecurityContext]`, используется fallback из `[ExecutionArtifacts]/SecurityLogPath`.

### [VersionDefaults] и version-overrides

Ключи в `[VersionDefaults]`:

- `RegistryPath`, `RegistryKeys`, `FilesystemPaths`
- `PrefetchPath`
- `EventLogs`, `ProcessEventIDs`, `NetworkEventIDs`
- `AmcachePath`, `AmcacheKeys`
- (опционально) `EnableInventoryApplication`, `EnableInventoryShortcut`, `AmcacheInventoryApplicationKey`, `AmcacheInventoryShortcutKey`

Overrides (`[Windows11]`, `[Windows10]`, `[Windows7]`, ...) содержат только отличия от `[VersionDefaults]`.

## 5. Практические профили

### 4.1 Быстрый и безопасный baseline

- Оставьте `EnableParallelStages = true`, `WorkerThreads = 4`.
- Не трогайте path/key overrides, если нет специфики образа.
- `EnableUnallocated = false`, если нет отдельного unallocated image.

### 4.2 Максимум сигналов

- Включите все `Enable* = true` в `[Recovery]` и `[ExecutionArtifacts]`.
- Оставьте native + fallback ключи включенными.
- Увеличьте `WorkerThreads`, `BinaryScanMaxMB`, `MaxCandidatesPerSource` при достаточных ресурсах.

### 4.3 Ускоренный прогон

- Временно выключите тяжелые источники (`EnableVSS`, `EnableHiber`, `EnableWindowsSearch`, `EnableSRUM`).
- Снизьте `BinaryScanMaxMB` и `MaxCandidatesPerSource`.
- Сократите `Versions` до реально ожидаемых.

## 6. Типичные ошибки

- Пустой/невалидный `[General]/Versions` -> OS detection не инициализируется.
- Удален ключ из `[VersionDefaults]` без override в `[WindowsXX]` -> этап пропускается с warning.
- Слишком маленькие лимиты (`BinaryScanMaxMB`, `MaxCandidatesPerSource`) -> потеря части evidence.
- Слишком большие лимиты на слабом диске -> долгий анализ.

## 7. Что изменено в текущем `config.ini`

Текущий `config.ini` в репозитории намеренно упрощен:

- удалены низкоуровневые path/key overrides, которые уже покрыты кодовыми default;
- оставлены обязательные и наиболее полезные ключи для ежедневной настройки;
- полный набор опциональных ключей описан в этом файле и может быть добавлен при необходимости.
