/// @file csv_exporter.cpp
/// @brief Реализация экспорта агрегированных артефактов в CSV.

#include "csv_exporter.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <set>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "analysis/artifacts/data/analysis_data.hpp"
#include "analysis/artifacts/common/evidence_utils.hpp"
#include "common/utils.hpp"
#include "errors/csv_export_exception.hpp"

namespace fs = std::filesystem;
using namespace PrefetchAnalysis;

namespace {

struct AggregatedData {
  std::string executable_name;  // Отображаемое имя исполняемого файла
  std::set<std::string> paths;  // Все пути для данного файла
  std::vector<std::string> run_times;
  std::set<std::string> autorun_locations;
  std::vector<WindowsDiskAnalysis::NetworkConnection> network_connections;
  std::vector<VolumeInfo> volumes;
  std::vector<FileMetric> metrics;
  uint32_t run_count = 0;
  std::set<std::string> versions;
  std::set<std::string> hashes;
  std::set<uint64_t> file_sizes;  // Размеры файлов
  bool has_deleted_trace = false;
  std::set<std::string> evidence_sources;
  std::set<std::string> tamper_flags;
  std::set<std::string> timeline_artifacts;
  std::set<std::string> recovered_from;
  std::string first_seen_utc;
  std::string last_seen_utc;
};

constexpr char kCsvDelimiter = ';';
constexpr std::string_view kListSeparator = " | ";

struct MetricFilterRules {
  std::size_t max_metric_names = 200;
  std::vector<std::string> skip_prefixes;
  std::vector<std::string> skip_contains;
  std::set<std::string> skip_exact;
  bool drop_short_upper_tokens = true;
  std::size_t short_upper_token_max_length = 3;
  bool drop_hex_like_tokens = true;
  std::size_t hex_like_min_length = 16;
  bool drop_upper_alnum_tokens = true;
  std::size_t upper_alnum_min_length = 8;
};

/// @brief Приводит ASCII-символ к нижнему регистру.
/// @param c Символ ASCII.
/// @return Нормализованный символ.
char toLowerAsciiChar(const unsigned char c) {
  if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
  return static_cast<char>(c);
}

/// @brief Приводит ASCII-строку к нижнему регистру.
/// @param value Исходная строка.
/// @return Копия строки в нижнем регистре.
std::string toLowerAscii(std::string value) {
  std::ranges::transform(value, value.begin(),
                         [](const unsigned char c) { return toLowerAsciiChar(c); });
  return value;
}

/// @brief Сортирует вектор и удаляет дубликаты.
/// @tparam T Тип элементов.
/// @param values Вектор значений (изменяется на месте).
template <typename T>
void sortAndUnique(std::vector<T>& values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

/// @brief Нормализует список фильтров метрик к lower-case без пустых значений.
/// @param values Исходные токены.
/// @return Отфильтрованный/нормализованный набор токенов.
std::vector<std::string> normalizeFilterTokens(
    const std::vector<std::string>& values) {
  std::vector<std::string> normalized;
  normalized.reserve(values.size());

  for (std::string token : values) {
    trim(token);
    token = toLowerAscii(std::move(token));
    if (!token.empty()) {
      normalized.push_back(std::move(token));
    }
  }

  sortAndUnique(normalized);
  return normalized;
}

/// @brief Строит runtime-правила фильтрации метрик из конфигурации.
/// @param options Настройки экспорта CSV.
/// @return Подготовленные правила для быстрого применения.
MetricFilterRules buildMetricFilterRules(
    const WindowsDiskAnalysis::CSVExportOptions& options) {
  MetricFilterRules rules;
  rules.max_metric_names = options.max_metric_names;
  rules.skip_prefixes = normalizeFilterTokens(options.metric_skip_prefixes);
  rules.skip_contains = normalizeFilterTokens(options.metric_skip_contains);

  for (const std::string& exact_value : options.metric_skip_exact) {
    std::string token = toLowerAscii(trim_copy(exact_value));
    if (!token.empty()) {
      rules.skip_exact.insert(std::move(token));
    }
  }

  rules.drop_short_upper_tokens = options.drop_short_upper_tokens;
  rules.short_upper_token_max_length =
      std::max<std::size_t>(1, options.short_upper_token_max_length);
  rules.drop_hex_like_tokens = options.drop_hex_like_tokens;
  rules.hex_like_min_length = std::max<std::size_t>(1, options.hex_like_min_length);
  rules.drop_upper_alnum_tokens = options.drop_upper_alnum_tokens;
  rules.upper_alnum_min_length =
      std::max<std::size_t>(1, options.upper_alnum_min_length);

  return rules;
}

/// @brief Проверяет, содержит ли имя файла расширение.
/// @param filename Имя файла.
/// @return `true`, если расширение присутствует.
bool hasFileExtension(const std::string& filename) {
  return filename.find('.') != std::string::npos;
}

/// @brief Проверяет, что строка состоит только из верхнего ASCII регистра.
/// @param value Проверяемая строка.
/// @return `true`, если все символы в диапазоне `A-Z`.
bool isAllUpperAsciiLetters(const std::string& value) {
  if (value.empty()) return false;

  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    if (ch < 'A' || ch > 'Z') return false;
  }

  return true;
}

/// @brief Определяет, похож ли токен на hex-like идентификатор.
/// @param value Проверяемая строка.
/// @param min_length Минимальная длина токена.
/// @return `true`, если строка похожа на hex-like шум.
bool isMostlyHexLikeToken(const std::string& value,
                          const std::size_t min_length) {
  if (value.size() < min_length) return false;

  bool has_digit = false;
  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    const bool is_hex =
        (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
        (ch >= 'A' && ch <= 'F') || ch == '_';
    if (!is_hex) return false;
    if (ch >= '0' && ch <= '9') has_digit = true;
  }

  return has_digit;
}

/// @brief Проверяет upper-alnum токен с `_`, характерный для шума.
/// @param value Проверяемая строка.
/// @param min_length Минимальная длина токена.
/// @return `true`, если токен удовлетворяет эвристике.
bool isUpperAlphaNumUnderscoreToken(const std::string& value,
                                    const std::size_t min_length) {
  if (value.size() < min_length) return false;

  bool has_digit = false;
  bool has_letter = false;
  for (const char ch_raw : value) {
    const unsigned char ch = static_cast<unsigned char>(ch_raw);
    const bool is_upper = (ch >= 'A' && ch <= 'Z');
    const bool is_digit = (ch >= '0' && ch <= '9');
    const bool is_separator = (ch == '_');

    if (!is_upper && !is_digit && !is_separator) return false;
    has_digit = has_digit || is_digit;
    has_letter = has_letter || is_upper;
  }

  return has_digit && has_letter;
}

/// @brief Проверяет отбрасывание имени по пользовательским правилам.
/// @param metric_filename_lower Имя метрики в lower-case.
/// @param rules Правила фильтрации.
/// @return `true`, если значение нужно исключить.
bool shouldSkipByUserRules(const std::string& metric_filename_lower,
                           const MetricFilterRules& rules) {
  if (rules.skip_exact.contains(metric_filename_lower)) {
    return true;
  }

  for (const std::string& prefix : rules.skip_prefixes) {
    if (metric_filename_lower.rfind(prefix, 0) == 0) {
      return true;
    }
  }

  for (const std::string& token : rules.skip_contains) {
    if (metric_filename_lower.find(token) != std::string::npos) {
      return true;
    }
  }

  return false;
}

/// @brief Проверяет необходимость отбрасывания имени метрики.
/// @param metric_filename Имя файла метрики.
/// @param rules Правила фильтрации.
/// @return `true`, если имя следует исключить.
bool shouldSkipMetricFilename(const std::string& metric_filename,
                              const MetricFilterRules& rules) {
  if (metric_filename.empty()) return true;

  const std::string lowered = toLowerAscii(metric_filename);
  if (shouldSkipByUserRules(lowered, rules)) return true;

  if (!hasFileExtension(metric_filename)) {
    if (rules.drop_short_upper_tokens &&
        metric_filename.size() <= rules.short_upper_token_max_length &&
        isAllUpperAsciiLetters(metric_filename)) {
      return true;
    }

    if (rules.drop_hex_like_tokens &&
        isMostlyHexLikeToken(metric_filename, rules.hex_like_min_length)) {
      return true;
    }

    if (rules.drop_upper_alnum_tokens &&
        isUpperAlphaNumUnderscoreToken(metric_filename,
                                       rules.upper_alnum_min_length)) {
      return true;
    }
  }

  return false;
}

/// @brief Формирует финальный набор метрик для CSV c фильтрами и лимитом.
/// @param metrics Список файловых метрик.
/// @param rules Правила фильтрации.
/// @return Набор имен для колонки `ФайловыеМетрики`.
std::vector<std::string> buildMetricValuesForCsv(
    const std::vector<FileMetric>& metrics, const MetricFilterRules& rules) {
  std::vector<std::string> metric_values;
  metric_values.reserve(metrics.size());

  for (const auto& metric : metrics) {
    fs::path file_path(metric.getFilename());
    std::string metric_filename = file_path.filename().string();
    metric_filename.erase(
        std::remove(metric_filename.begin(), metric_filename.end(), '\0'),
        metric_filename.end());
    trim(metric_filename);
    if (shouldSkipMetricFilename(metric_filename, rules)) continue;
    metric_values.push_back(std::move(metric_filename));
  }

  sortAndUnique(metric_values);

  if (rules.max_metric_names > 0 && metric_values.size() > rules.max_metric_names) {
    const std::size_t hidden_count = metric_values.size() - rules.max_metric_names;
    metric_values.resize(rules.max_metric_names);
    metric_values.push_back("[+" + std::to_string(hidden_count) + " скрыто]");
  }

  return metric_values;
}

/// @brief Нормализует путь/командную строку до пути исполняемого файла.
/// @param path Исходная строка.
/// @return Нормализованный путь или пустая строка.
std::string normalizePath(const std::string& path) {
  if (path.empty()) return "";

  std::string result = path;

  // Если вместо чистого пути пришла командная строка, вырезаем исполняемый
  // файл.
  trim(result);
  if (!result.empty() && (result.front() == '"' || result.front() == '\'')) {
    const char quote = result.front();
    if (const size_t quote_end = result.find(quote, 1);
        quote_end != std::string::npos) {
      result = result.substr(1, quote_end - 1);
    }
  } else {
    const std::string lowered = toLowerAscii(result);
    for (const std::string ext : {".exe", ".dll", ".sys", ".com", ".bat",
                                  ".cmd"}) {
      if (const size_t ext_pos = lowered.find(ext);
          ext_pos != std::string::npos) {
        result = result.substr(0, ext_pos + ext.size());
        break;
      }
    }
  }

  std::ranges::replace(result, '/', '\\');

  // Удаление начальных и конечных пробелов/кавычек
  auto start = result.find_first_not_of(" \"");
  auto end = result.find_last_not_of(" \"");

  if (start == std::string::npos || end == std::string::npos) return "";

  return result.substr(start, end - start + 1);
}

/// @brief Извлекает имя файла из полного пути.
/// @param path Полный или относительный путь.
/// @return Имя файла.
std::string getFilenameFromPath(const std::string& path) {
  if (path.empty()) return {};
  std::string normalized = path;
  std::ranges::replace(normalized, '\\', '/');
  const size_t sep_pos = normalized.find_last_of('/');
  if (sep_pos == std::string::npos) return normalized;
  return normalized.substr(sep_pos + 1);
}

/// @brief Преобразует тип тома в строковое представление.
/// @param type Числовой `VolumeType`.
/// @return Человеко-читаемое обозначение типа тома.
std::string volumeTypeToString(uint32_t type) {
  switch (static_cast<VolumeType>(type)) {
    case VolumeType::FIXED:
      return "FIXED";
    case VolumeType::REMOVABLE:
      return "REMOVABLE";
    case VolumeType::NETWORK:
      return "NETWORK";
    case VolumeType::OPTICAL:
      return "CDROM";
    case VolumeType::RAMDISK:
      return "RAM";
    case VolumeType::SYSTEM:
      return "SYSTEM";
    case VolumeType::TEMPORARY:
      return "TEMPORARY";
    case VolumeType::VIRTUAL:
      return "VIRTUAL";
    default:
      return "UNKNOWN";
  }
}

/// @brief Нормализует имя источника артефакта к каноническому виду.
/// @param source Исходное имя источника.
/// @return Каноническое имя источника.
std::string normalizeEvidenceSource(std::string source) {
  trim(source);
  if (source.empty()) return {};

  static const std::unordered_map<std::string, std::string_view>
      kCanonicalEvidenceSources = {
          {"prefetch", "Prefetch"},
          {"eventlog", "EventLog"},
          {"event log", "EventLog"},
          {"amcache", "Amcache"},
          {"autorun", "Autorun"},
          {"networkevent", "NetworkEvent"},
          {"network event", "NetworkEvent"},
          {"userassist", "UserAssist"},
          {"runmru", "RunMRU"},
          {"featureusage", "FeatureUsage"},
          {"feature usage", "FeatureUsage"},
          {"bam", "BAM"},
          {"dam", "DAM"},
          {"shimcache", "ShimCache"},
          {"recentapps", "RecentApps"},
          {"recent apps", "RecentApps"},
          {"taskscheduler", "TaskScheduler"},
          {"task scheduler", "TaskScheduler"},
          {"ifeo", "IFEO"},
          {"wer", "WER"},
          {"timeline", "Timeline"},
          {"bits", "BITS"},
          {"wmirepository", "WMIRepository"},
          {"wmi repository", "WMIRepository"},
          {"windowssearch", "WindowsSearch"},
          {"windows search", "WindowsSearch"},
          {"jumplist", "JumpList"},
          {"jump list", "JumpList"},
          {"lnkrecent", "LNKRecent"},
          {"lnk recent", "LNKRecent"},
          {"srum", "SRUM"},
          {"usn", "USN"},
          {"$logfile", "$LogFile"},
          {"logfile", "$LogFile"},
          {"vss", "VSS"},
          {"pagefile", "Pagefile"},
          {"memory", "Memory"},
          {"unallocated", "Unallocated"},
      };

  const std::string lowered = toLowerAscii(source);
  const auto it = kCanonicalEvidenceSources.find(lowered);
  if (it != kCanonicalEvidenceSources.end()) {
    return std::string(it->second);
  }
  return source;
}

/// @brief Добавляет источник артефактов с нормализацией имени.
/// @param data Агрегированные данные строки.
/// @param source Источник для добавления.
void addEvidenceSource(AggregatedData& data, std::string source) {
  source = normalizeEvidenceSource(std::move(source));
  if (!source.empty()) {
    data.evidence_sources.insert(std::move(source));
  }
}

/// @brief Добавляет tamper-флаг, если он не пуст.
/// @param data Агрегированные данные строки.
/// @param flag Имя флага.
void addTamperFlag(AggregatedData& data, std::string flag) {
  trim(flag);
  if (!flag.empty()) {
    data.tamper_flags.insert(std::move(flag));
  }
}

/// @brief Проверяет наличие конкретного источника в строке.
/// @param data Агрегированные данные строки.
/// @param source Искомый источник.
/// @return `true`, если источник найден.
bool hasEvidenceSource(const AggregatedData& data, const std::string& source) {
  return data.evidence_sources.contains(normalizeEvidenceSource(source));
}

/// @brief Проверяет наличие любого источника из заданного списка.
/// @param data Агрегированные данные строки.
/// @param sources Набор источников для проверки.
/// @return `true`, если найден хотя бы один источник.
bool hasAnyEvidenceSource(const AggregatedData& data,
                          const std::vector<std::string>& sources) {
  for (const auto& source : sources) {
    if (hasEvidenceSource(data, source)) return true;
  }
  return false;
}

/// @brief Проверяет, похоже ли имя на образ процесса (`*.exe/...`).
/// @param executable_name Имя процесса.
/// @return `true`, если имя соответствует исполняемому образу.
bool isLikelyProcessImageName(const std::string& executable_name) {
  const std::string lowered = toLowerAscii(executable_name);
  for (const std::string_view ext :
       {".exe", ".com", ".bat", ".cmd", ".ps1", ".msi"}) {
    if (lowered.size() >= ext.size() &&
        lowered.rfind(ext) == lowered.size() - ext.size()) {
      return true;
    }
  }
  return false;
}

/// @brief Выводит дополнительные tamper-флаги по правилам корреляции.
/// @param data Агрегированные данные строки.
/// @param options Параметры правил tamper.
void deriveTamperFlags(
    AggregatedData& data, const WindowsDiskAnalysis::CSVExportOptions& options) {
  if (options.tamper_rule_prefetch_missing_enabled) {
    const bool has_prefetch = hasEvidenceSource(data, "Prefetch");
    const bool has_runtime_sources = hasAnyEvidenceSource(
        data, options.tamper_prefetch_missing_runtime_sources);
    const bool image_condition =
        !options.tamper_rule_prefetch_missing_require_process_image ||
        isLikelyProcessImageName(data.executable_name);

    if (!has_prefetch && has_runtime_sources && image_condition) {
      addTamperFlag(data, "prefetch_missing_but_other_artifacts_present");
    }
  }

  if (options.tamper_rule_amcache_deleted_trace_enabled && data.has_deleted_trace) {
    addTamperFlag(data, "amcache_deleted_trace");
  }

  if (options.tamper_rule_registry_inconsistency_enabled) {
    const bool has_registry_only_sources =
        hasAnyEvidenceSource(data, options.tamper_registry_only_sources);
    const bool has_strong_correlated_sources =
        hasAnyEvidenceSource(data, options.tamper_registry_strong_sources);
    if (has_registry_only_sources && !has_strong_correlated_sources) {
      addTamperFlag(data, "registry_inconsistency");
    }
  }
}

/// @brief Обновляет минимальное время первого наблюдения.
/// @param data Агрегированные данные строки.
/// @param timestamp Временная метка-кандидат.
void updateRowFirstSeen(AggregatedData& data, const std::string& timestamp) {
  WindowsDiskAnalysis::EvidenceUtils::updateTimestampMin(data.first_seen_utc,
                                                         timestamp);
}

/// @brief Обновляет максимальное время последнего наблюдения.
/// @param data Агрегированные данные строки.
/// @param timestamp Временная метка-кандидат.
void updateRowLastSeen(AggregatedData& data, const std::string& timestamp) {
  WindowsDiskAnalysis::EvidenceUtils::updateTimestampMax(data.last_seen_utc,
                                                         timestamp);
}

}  // namespace

namespace WindowsDiskAnalysis {

void CSVExporter::exportToCSV(
    const std::string& output_path,
    const std::vector<AutorunEntry>& autorun_entries,
    const std::map<std::string, ProcessInfo>& process_data,
    const std::vector<NetworkConnection>& network_connections,
    const std::vector<AmcacheEntry>& amcache_entries,
    const CSVExportOptions& options) {
  std::ofstream file(output_path, std::ios::binary);
  if (!file.is_open()) {
    throw FileOpenException(output_path);
  }

  try {
    const MetricFilterRules metric_rules = buildMetricFilterRules(options);

    auto escape = [](const std::string& s) {
      if (s.empty()) return std::string();

      std::string result;
      result.reserve(s.size() + 2);
      result += '"';

      for (char c : s) {
        if (c == '\n' || c == '\r') {
          result += ' ';
          continue;
        }

        if (c == '"')
          result += "\"\"";
        else
          result += c;
      }

      result += '"';
      return result;
    };

    auto joinStrings = [](const auto& container) {
      std::string out;
      bool first = true;
      for (const auto& value : container) {
        if (value.empty()) continue;
        if (!first) out += kListSeparator;
        out += value;
        first = false;
      }
      return out;
    };

    // BOM нужен для корректного чтения UTF-8 заголовков в Excel/Windows
    file.write("\xEF\xBB\xBF", 3);

    // Заголовок CSV
    file << "ИсполняемыйФайл" << kCsvDelimiter << "Пути" << kCsvDelimiter
         << "Версии" << kCsvDelimiter << "Хэши" << kCsvDelimiter
         << "РазмерФайла" << kCsvDelimiter << "ВременаЗапуска" << kCsvDelimiter
         << "FirstSeenUTC" << kCsvDelimiter << "LastSeenUTC" << kCsvDelimiter
         << "TimelineArtifacts" << kCsvDelimiter << "RecoveredFrom"
         << kCsvDelimiter << "Автозагрузка" << kCsvDelimiter << "СледыУдаления"
         << kCsvDelimiter << "КоличествоЗапусков" << kCsvDelimiter
         << "Тома(серийный:тип)" << kCsvDelimiter << "СетевыеПодключения"
         << kCsvDelimiter << "ФайловыеМетрики" << kCsvDelimiter
         << "EvidenceSources" << kCsvDelimiter << "TamperFlags\n";

    // Основная карта для агрегации данных по нормализованному идентификатору
    // процесса.
    // Приоритет: полный путь (если есть), иначе имя файла.
    std::map<std::string, AggregatedData> aggregated_data;

    // Обработка всех типов данных с объединением по имени файла
    auto processEntry = [&](const std::string& path, auto processor) {
      std::string norm_path = normalizePath(path);
      if (norm_path.empty()) return;

      // Получаем имя файла - основной ключ для агрегации
      std::string filename = getFilenameFromPath(norm_path);
      if (filename.empty()) return;

      const bool has_explicit_path =
          norm_path.find('\\') != std::string::npos ||
          norm_path.find('/') != std::string::npos ||
          (norm_path.size() >= 3 &&
           std::isalpha(static_cast<unsigned char>(norm_path[0])) != 0 &&
           norm_path[1] == ':' &&
           (norm_path[2] == '\\' || norm_path[2] == '/'));
      const std::string aggregation_key =
          toLowerAscii(has_explicit_path ? norm_path : filename);

      // Обрабатываем данные
      auto& bucket = aggregated_data[aggregation_key];
      if (bucket.executable_name.empty()) {
        bucket.executable_name = filename;
      }

      processor(bucket, norm_path);
    };

    // 1. Обрабатываем данные автозагрузки
    for (const auto& entry : autorun_entries) {
      processEntry(entry.path,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.autorun_locations.insert(entry.location);
                     addEvidenceSource(data, "Autorun");
                     data.timeline_artifacts.insert("[Autorun] " + entry.location);
                   });
    }

    // 2. Обрабатываем данные процессов
    for (const auto& [path, info] : process_data) {
      processEntry(
          path, [&](AggregatedData& data, const std::string& normalized_path) {
            data.paths.insert(normalized_path);
            data.run_times.insert(data.run_times.end(), info.run_times.begin(),
                                  info.run_times.end());
            data.run_count += info.run_count;
            data.volumes.insert(data.volumes.end(), info.volumes.begin(),
                                info.volumes.end());
            data.metrics.insert(data.metrics.end(), info.metrics.begin(),
                                info.metrics.end());

            for (const auto& source : info.evidence_sources) {
              addEvidenceSource(data, source);
            }
            for (const auto& flag : info.tamper_flags) {
              addTamperFlag(data, flag);
            }
            for (const auto& timeline : info.timeline_artifacts) {
              if (!timeline.empty()) {
                data.timeline_artifacts.insert(timeline);
              }
            }
            for (const auto& recovered_from : info.recovered_from) {
              if (!recovered_from.empty()) {
                data.recovered_from.insert(recovered_from);
              }
            }

            updateRowFirstSeen(data, info.first_seen_utc);
            updateRowLastSeen(data, info.last_seen_utc);
            for (const auto& timestamp : info.run_times) {
              updateRowFirstSeen(data, timestamp);
              updateRowLastSeen(data, timestamp);
            }

            // Fallback для старых источников, где evidence_sources еще не
            // заполнены на этапе сбора.
            if (info.evidence_sources.empty()) {
              if (!info.metrics.empty() || !info.volumes.empty()) {
                addEvidenceSource(data, "Prefetch");
              } else if (info.run_count > 0 || !info.run_times.empty()) {
                addEvidenceSource(data, "EventLog");
              }
            }

          });
    }

    // 3. Обрабатываем сетевые подключения
    for (const auto& conn : network_connections) {
      processEntry(conn.process_name,
                   [&](AggregatedData& data, const std::string& path) {
                     data.paths.insert(path);
                     data.network_connections.push_back(conn);
                     addEvidenceSource(data, "NetworkEvent");
                     data.timeline_artifacts.insert(
                         "[NetworkEvent] " + conn.protocol + ":" +
                         conn.local_address + "->" + conn.remote_address + ":" +
                         std::to_string(conn.port));
                   });
    }

    // 4. Обрабатываем данные Amcache - добавляем версии, хэши, размеры и время
    // изменения
    for (const auto& entry : amcache_entries) {
      // Используем file_path как основной идентификатор
      std::string path = entry.file_path;
      if (path.empty() && !entry.name.empty()) {
        path = entry.name;  // fallback на имя файла
      }
      if (path.empty()) continue;  // пропускаем если нет идентификатора

      processEntry(path,
                   [&](AggregatedData& data, const std::string& norm_path) {
                     data.paths.insert(norm_path);
                     addEvidenceSource(data, "Amcache");

                     // Добавляем версии и хэши
                     if (!entry.version.empty()) {
                       data.versions.insert(entry.version);
                     }
                     if (!entry.file_hash.empty()) {
                       data.hashes.insert(entry.file_hash);
                     }

                     // Добавляем размеры файлов
                     if (entry.file_size > 0) {
                       data.file_sizes.insert(entry.file_size);
                     }

                     if (!entry.modification_time_str.empty()) {
                       data.run_times.push_back(entry.modification_time_str);
                       updateRowFirstSeen(data, entry.modification_time_str);
                       updateRowLastSeen(data, entry.modification_time_str);
                       data.timeline_artifacts.insert(
                           "[Amcache] " + entry.modification_time_str);
                     }

                     if (entry.is_deleted) {
                       data.has_deleted_trace = true;
                     }
                   });
    }

    // 5. Генерируем выходные данные
    for (const auto& [aggregation_key, data] : aggregated_data) {
      AggregatedData row = data;
      deriveTamperFlags(row, options);

      const std::string& filename =
          row.executable_name.empty() ? aggregation_key : row.executable_name;

      std::string paths_str = joinStrings(row.paths);
      std::string versions_str = joinStrings(row.versions);
      std::string hashes_str = joinStrings(row.hashes);

      std::vector<std::string> file_sizes;
      file_sizes.reserve(row.file_sizes.size());
      for (const auto size : row.file_sizes) {
        file_sizes.push_back(std::to_string(size));
      }
      std::string file_sizes_str = joinStrings(file_sizes);

      // Форматирование времени запуска (включая время изменения)
      std::vector<std::string> unique_run_times = row.run_times;
      sortAndUnique(unique_run_times);
      std::string run_times_str = joinStrings(unique_run_times);

      // Форматирование автозагрузки
      std::string autorun_str;
      if (!row.autorun_locations.empty()) {
        autorun_str = "Да(";
        bool first_location = true;
        for (const auto& location : row.autorun_locations) {
          if (!first_location) autorun_str += ", ";
          autorun_str += location;
          first_location = false;
        }
        autorun_str += ")";
      } else {
        autorun_str = "Нет";
      }

      // Следы удалённых файлов
      std::string deleted_str = row.has_deleted_trace ? "Да" : "Нет";

      // Форматирование сетевых подключений
      std::vector<std::string> network_values;
      network_values.reserve(row.network_connections.size());
      for (const auto& conn : row.network_connections) {
        network_values.push_back(conn.protocol + ":" + conn.local_address +
                                 "->" + conn.remote_address + ":" +
                                 std::to_string(conn.port));
      }
      sortAndUnique(network_values);
      std::string network_str = joinStrings(network_values);

      // Форматирование томов
      std::vector<std::string> volume_values;
      volume_values.reserve(row.volumes.size());
      for (const auto& vol : row.volumes) {
        volume_values.push_back(std::to_string(vol.getSerialNumber()) + ":" +
                                volumeTypeToString(vol.getVolumeType()));
      }
      sortAndUnique(volume_values);
      std::string volumes_str = joinStrings(volume_values);

      // Форматирование файловых метрик
      std::vector<std::string> metric_values =
          buildMetricValuesForCsv(row.metrics, metric_rules);
      std::string metrics_str = joinStrings(metric_values);

      std::string timeline_artifacts_str = joinStrings(row.timeline_artifacts);
      std::string recovered_from_str = joinStrings(row.recovered_from);
      std::string evidence_sources_str = joinStrings(row.evidence_sources);
      std::string tamper_flags_str = joinStrings(row.tamper_flags);

      // Запись данных в строго фиксированном порядке колонок
      file << escape(filename) << kCsvDelimiter << escape(paths_str)
           << kCsvDelimiter << escape(versions_str) << kCsvDelimiter
           << escape(hashes_str) << kCsvDelimiter << escape(file_sizes_str)
           << kCsvDelimiter << escape(run_times_str) << kCsvDelimiter
           << escape(row.first_seen_utc) << kCsvDelimiter
           << escape(row.last_seen_utc) << kCsvDelimiter
           << escape(timeline_artifacts_str) << kCsvDelimiter
           << escape(recovered_from_str) << kCsvDelimiter << escape(autorun_str)
           << kCsvDelimiter << escape(deleted_str)
           << kCsvDelimiter << row.run_count << kCsvDelimiter
           << escape(volumes_str) << kCsvDelimiter << escape(network_str)
           << kCsvDelimiter << escape(metrics_str) << kCsvDelimiter
           << escape(evidence_sources_str) << kCsvDelimiter
           << escape(tamper_flags_str) << "\n";
    }
  } catch (const std::exception& e) {
    throw CsvExportException(std::string("Ошибка при экспорте данных: ") +
                             e.what());
  }
}

}
