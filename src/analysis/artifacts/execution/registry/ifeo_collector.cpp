/// @file ifeo_collector.cpp
/// @brief Реализация IfeoCollector.
#include "ifeo_collector.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "analysis/artifacts/common/evidence_utils.hpp"
#include "analysis/artifacts/execution/execution_evidence_helpers.hpp"
#include "common/utils.hpp"
#include "infra/logging/logger.hpp"
#include "parsers/registry/parser/parser.hpp"

namespace fs = std::filesystem;

namespace WindowsDiskAnalysis {

using namespace ExecutionEvidenceDetail;
using EvidenceUtils::extractExecutableFromCommand;
using EvidenceUtils::toLowerAscii;

void IfeoCollector::collect(const ExecutionEvidenceContext& ctx,
                            std::unordered_map<std::string, ProcessInfo>& process_data) {
  if (!ctx.config.enable_ifeo) return;
  if (ctx.software_hive_path.empty()) return;
  const auto logger = GlobalLogger::get();
  RegistryAnalysis::RegistryParser local_parser;

  auto normalize_target_image = [&](std::string image_name)
      -> std::optional<std::string> {
    trim(image_name);
    if (image_name.empty()) return std::nullopt;
    std::ranges::replace(image_name, '/', '\\');

    if (auto executable = extractExecutableFromCommand(image_name);
        executable.has_value()) {
      return executable;
    }

    const std::string lowered = toLowerAscii(image_name);
    for (const std::string ext : {".exe", ".com", ".bat", ".cmd", ".ps1",
                                  ".msi"}) {
      if (lowered.size() >= ext.size() &&
          lowered.rfind(ext) == lowered.size() - ext.size()) {
        return image_name;
      }
    }
    return std::nullopt;
  };

  std::size_t collected = 0;
  std::unordered_set<std::string> processed_images;
  std::vector<std::string> ifeo_roots = {ctx.config.ifeo_root_key};
  if (!ctx.config.ifeo_wow6432_root_key.empty()) {
    ifeo_roots.push_back(ctx.config.ifeo_wow6432_root_key);
  }

  for (const std::string& ifeo_root : ifeo_roots) {
    if (ifeo_root.empty()) continue;

    std::vector<std::string> image_keys;
    try {
      image_keys = local_parser.listSubkeys(ctx.software_hive_path, ifeo_root);
    } catch (...) {
      continue;
    }

    for (const auto& image_key : image_keys) {
      if (collected >= ctx.config.max_candidates_per_source) break;

      const auto target_opt = normalize_target_image(image_key);
      if (!target_opt.has_value()) continue;
      const std::string target = *target_opt;
      if (!processed_images.insert(toLowerAscii(ifeo_root + "|" + target)).second) {
        continue;
      }

      const std::string full_key = ifeo_root + "/" + image_key;
      std::vector<std::unique_ptr<RegistryAnalysis::IRegistryData>> values;
      try {
        values = local_parser.getKeyValues(ctx.software_hive_path, full_key);
      } catch (...) {
        continue;
      }

      bool has_debugger = false;
      std::string debugger_command;
      std::vector<std::string> notes;

      for (const auto& value : values) {
        const std::string name = getLastPathComponent(value->getName(), '/');
        const std::string name_lower = toLowerAscii(name);
        std::string data = value->getDataAsString();
        trim(data);

        if (name_lower == "debugger" && !data.empty()) {
          has_debugger = true;
          debugger_command = data;
          notes.push_back("Debugger=" + data);
        } else if (name_lower == "globalflag" && !data.empty()) {
          notes.push_back("GlobalFlag=" + data);
        } else if ((name_lower == "verifierdlls" ||
                    name_lower == "mitigationoptions") &&
                   !data.empty()) {
          notes.push_back(name + "=" + data);
        }
      }

      if (!has_debugger && notes.empty()) continue;

      std::string details = "ifeo_root=" + ifeo_root + ", ifeo=" + image_key;
      if (!notes.empty()) {
        details += ", ";
        for (std::size_t i = 0; i < notes.size(); ++i) {
          if (i > 0) details += "; ";
          details += notes[i];
        }
      }
      addExecutionEvidence(process_data, target, "IFEO", "", details);
      collected++;

      if (has_debugger) {
        auto& info = ensureProcessInfo(process_data, target);
        appendTamperFlag(info.tamper_flags, "ifeo_debugger_hijack");

        if (auto debugger_executable =
                extractExecutableFromCommand(debugger_command);
            debugger_executable.has_value()) {
          addExecutionEvidence(process_data, *debugger_executable, "IFEO", "",
                              "ifeo-debugger-for=" + target);
        }
      }
    }
  }

  logger->info("IFEO: добавлено {} кандидат(ов)", collected);
}

}  // namespace WindowsDiskAnalysis
