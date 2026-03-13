# Configuration

Справочник по `config.ini` для `Program traces`.

## Как читается конфиг

Программа использует два уровня настроек:

- глобальные секции (`[General]`, `[Logging]`, `[Recovery]`, `[ExecutionArtifacts]` и т.д.);
- версионные override-секции (`[WindowsXP]`, `[Windows7]`, `[Windows11]`, `[WindowsServer]`).

Для путей и списков артефактов действует правило fallback:

1. сначала читается ключ из секции конкретной версии Windows;
2. если ключ пустой или отсутствует, используется `[VersionDefaults]`.

## Основные секции

### `[General]`

- `Versions` — порядок проверки версий Windows в детекторе ОС.

### `[Logging]`

Флаги детального логирования по этапам:

- `DebugOSDetection`
- `DebugAutorun`
- `DebugPrefetch`
- `DebugEventLog`
- `DebugAmcache`
- `DebugExecution`
- `DebugRecovery`

### `[Performance]`

- `EnableParallelStages` — параллельный запуск независимых этапов/групп.
- `WorkerThreads` — верхний лимит рабочих потоков.
- `MaxIOWorkers` — лимит IO-задач.
- `EnableParallelPrefetch`
- `EnableParallelEventLog`
- `EnableParallelUserHives`

### `[CSVExport]`

Управляет фильтрацией шумных токенов в колонке файловых метрик:

- `MetricMaxNames`
- `MetricSkipPrefixes`
- `MetricSkipContains`
- `MetricSkipExact`
- `DropShortUpperTokens`
- `ShortUpperTokenMaxLength`
- `DropHexLikeTokens`
- `HexLikeMinLength`
- `DropUpperAlnumTokens`
- `UpperAlnumMinLength`

## Tamper rules

### `[TamperRules]`

- `EnablePrefetchMissingRule` — флаг `prefetch_missing_but_other_artifacts_present`.
- `PrefetchMissingRequireProcessImage` — правило срабатывает только если известен путь/имя исполняемого файла.
- `PrefetchMissingRuntimeSources` — источники, считающиеся runtime-доказательством запуска.
- `EnableSIFNDivergenceCheck` — включает проверку расхождения `$STANDARD_INFORMATION` и `$FILE_NAME`.
- `TimestampDivergenceThresholdSec` — порог расхождения во времени создания.
- `EnableAmcacheDeletedTraceRule` — флаг для удаленных артефактов Amcache.
- `EnableRegistryInconsistencyRule` — флаг для конфликтов между registry-only и strong sources.
- `RegistryOnlySources`
- `RegistryStrongSources`

## Recovery

### `[Recovery]`

Блок восстановления удаленных или слабо доступных следов.

Переключатели источников:

- `EnableUSN`
- `EnableVSS`
- `EnableHiber`
- `EnableNTFSMetadata`
- `EnableRegistryLogsRecovery`
- `EnableLogFile`
- `EnablePagefile`
- `EnableMemory`
- `EnableUnallocated`

Native/fallback режимы:

- `EnableNativeUSNParser`
- `USNFallbackToBinaryOnNativeFailure`
- `EnableNativeVSSParser`
- `VSSFallbackToBinaryOnNativeFailure`
- `EnableVSSSnapshotReplay`
- `EnableNativeHiberParser`
- `HiberFallbackToBinary`
- `EnableNativeFsntfsParser`
- `FsntfsFallbackToBinaryOnNativeFailure`

Лимиты и пути:

- `USNNativeMaxRecords`
- `USNJournalPath`
- `VSSNativeMaxStores`
- `VSSSnapshotReplayMaxFiles`
- `VSSVolumePath`
- `HiberMaxPages`
- `HiberPath`
- `MFTPath`
- `MFTMaxRecords`
- `MFTRecordSize`
- `BitmapPath`
- `RegistryConfigPath`
- `UnallocatedImagePath`
- `BinaryScanMaxMB`
- `MaxCandidatesPerSource`

## Execution artifacts

### `[ExecutionArtifacts]`

Переключатели коллекторов:

- `EnableShimCache`
- `EnableUserAssist`
- `EnableRunMRU`
- `EnableFeatureUsage`
- `EnableRecentApps`
- `EnableBamDam`
- `EnableServices`
- `EnableHostsFile`
- `EnableNetworkProfiles`
- `EnableFirewallRules`
- `IncludeInactiveFirewallRules`
- `EnableJumpLists`
- `EnableLnkRecent`
- `EnableTaskScheduler`
- `EnableIFEO`
- `EnableWER`
- `EnableTimeline`
- `EnableBITS`
- `EnableWMIRepository`
- `EnableWindowsSearch`
- `EnableNativeWindowsSearchParser`
- `WindowsSearchFallbackToBinaryOnNativeFailure`
- `EnableSRUM`
- `EnableNativeSRUM`
- `SrumFallbackToBinaryOnNativeFailure`
- `EnableMuiCache`
- `EnableAppCompatFlags`
- `EnableTypedPaths`
- `EnableLastVisitedMRU`
- `EnableOpenSaveMRU`
- `EnablePSHistory`
- `EnableSecurityLogTamperCheck`

Лимиты native database parsers:

- `WindowsSearchNativeMaxRecordsPerTable`
- `SrumNativeMaxRecordsPerTable`
- `WindowsSearchTableAllowlist`
- `SrumTableAllowlist`

Пути к registry keys и файловым артефактам:

- `UserAssistKey`
- `RunMRUKey`
- `FeatureUsageAppSwitchedKey`
- `FeatureUsageShowJumpViewKey`
- `FeatureUsageAppBadgeUpdatedKey`
- `RecentAppsRootKey`
- `RecentAppsRecentItemsSuffix`
- `ShimCacheValuePath`
- `MuiCacheKey`
- `AppCompatLayersKey`
- `AppCompatAssistKey`
- `TypedPathsKey`
- `LastVisitedMruKey`
- `OpenSaveMruKey`
- `PSHistorySuffix`
- `BamRootPath`
- `DamRootPath`
- `BamLegacyRootPath`
- `DamLegacyRootPath`
- `ServicesRootPath`
- `NetworkProfilesRootKey`
- `NetworkSignatureRoots`
- `FirewallRulesKeys`
- `RecentLnkPath`
- `JumpListAutoPath`
- `JumpListCustomPath`
- `TaskSchedulerPath`
- `TaskCacheTasksKey`
- `TaskCacheTreeKey`
- `IFEORootKey`
- `IFEOWow6432RootKey`
- `WERProgramDataPath`
- `WERUserPath`
- `TimelineRootPath`
- `BITSDownloaderPath`
- `HostsFilePath`
- `WMIRepositoryPath`
- `WindowsSearchPath`
- `SRUMPath`
- `SecurityLogPath`

## Security context

### `[SecurityContext]`

Корреляция процессов с logon session и привилегиями:

- `Enabled`
- `SecurityLogPath`
- `ProcessCreateEventIDs`
- `LogonEventIDs`
- `PrivilegeEventIDs`
- `LogonCorrelationWindowSeconds`
- `PidCorrelationWindowSeconds`

## OS detection

### `[OSInfoRegistryPaths]`

Путь к `SOFTWARE` hive по версии Windows.

### `[OSInfoSystemRegistryPaths]`

Путь к `SYSTEM` hive для определения `ProductType`.

### `[OSInfoHive]`

- `Default` — путь к `Microsoft/Windows NT/CurrentVersion`.

### `[OSInfoKeys]`

Список значений, которые читаются из `CurrentVersion`:

- `ProductName`
- `InstallationType`
- `CurrentBuild`
- `CurrentBuildNumber`
- `ReleaseId`
- `DisplayVersion`
- `EditionID`
- `CurrentVersion`
- `CSDVersion`

### `[BuildMappingsClient]` и `[BuildMappingsServer]`

Пороговые сборки для классификации семейства ОС.

### `[OSKeywords]`

- `DefaultServerKeywords` — fallback-слова для server edition.

## Version defaults и overrides

### `[VersionDefaults]`

Базовые пути и ключи для артефактов:

- `RegistryPath`
- `RegistryKeys`
- `FilesystemPaths`
- `PrefetchPath`
- `EventLogs`
- `ProcessEventIDs`
- `NetworkEventIDs`
- `AmcachePath`
- `AmcacheKeys`

### `[Windows7]`

Дополнительно поддерживается:

- `RecentFileCachePath` — fallback для систем без `Amcache.hve`.

### `[WindowsVista]` и `[WindowsXP]`

`AmcachePath` и `AmcacheKeys` обычно оставляются пустыми.

### `[Windows10]`, `[Windows11]`, `[WindowsServer]`

Используйте эти секции только для отличий от `[VersionDefaults]`.

## Пример минимальной настройки для Windows 7

```ini
[Windows7]
ProcessEventIDs = 4688
NetworkEventIDs = 5156
RecentFileCachePath = Windows/AppCompat/Programs/RecentFileCache.bcf
AmcachePath = Windows/appcompat/Programs/Amcache.hve
AmcacheKeys = Root/InventoryApplicationFile
```

## Практика изменения конфигурации

1. Меняйте только нужные секции версии, не копируйте весь `config.ini`.
2. При добавлении нового execution-коллектора сначала заведите переключатель в `[ExecutionArtifacts]`.
3. Если ключ зависит от версии Windows, добавьте override в `[WindowsXX]`, а общее значение оставьте в `[VersionDefaults]`.
4. После изменения конфига проверяйте запуск через `./build/program_traces --help` и тесты через `ctest --test-dir build --output-on-failure`.
