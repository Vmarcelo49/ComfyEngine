#include "core/AutoAssembler.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace core {

namespace {

std::string trimCopy(const std::string &s) {
    std::string out = s;
    out.erase(out.begin(), std::find_if(out.begin(), out.end(), [](unsigned char c) { return !std::isspace(c); }));
    out.erase(std::find_if(out.rbegin(), out.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), out.end());
    return out;
}

std::string toLower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
    return str;
}

std::string addrToHex(uintptr_t addr) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(addr));
    return buf;
}

} // namespace

AutoAssembler::AutoAssembler(CodeInjector &injector) : injector_(injector) {}

std::optional<AutoAssembler::Command> AutoAssembler::parseLine(
    const std::string &line, const std::unordered_map<std::string, uintptr_t> &symbols, std::string &errorOut) {
    if (line.empty()) return std::nullopt;
    if (line[0] == ';' || line[0] == '#') return std::nullopt;
    if (line.size() >= 2 && line[0] == '/' && line[1] == '/') return std::nullopt;
    std::istringstream ls(line);
    std::string word;
    if (!(ls >> word)) return std::nullopt;
    Command cmd;
    if (word == "patch") {
        cmd.type = Command::Type::Patch;
    } else if (word == "restore") {
        cmd.type = Command::Type::Restore;
    } else {
        errorOut = "Unknown directive: " + word;
        return std::nullopt;
    }
    std::string addrStr;
    if (!(ls >> addrStr)) {
        errorOut = "Missing address";
        return std::nullopt;
    }
    errno = 0;
    char *end = nullptr;
    unsigned long long literal = std::strtoull(addrStr.c_str(), &end, 0);
    if (end != addrStr.c_str() && *end == '\0' && literal != 0) {
        cmd.address = static_cast<uintptr_t>(literal);
    } else {
        size_t posPlus = addrStr.find('+');
        size_t posMinus = addrStr.find('-', 1);
        size_t pos = std::min(posPlus == std::string::npos ? addrStr.size() : posPlus,
                              posMinus == std::string::npos ? addrStr.size() : posMinus);
        std::string name = addrStr.substr(0, pos);
        auto it = symbols.find(name);
        if (it == symbols.end()) {
            errorOut = "Unknown symbol: " + name;
            return std::nullopt;
        }
        uintptr_t base = it->second;
        int64_t offset = 0;
        if (pos < addrStr.size()) {
            std::string offStr = addrStr.substr(pos);
            char sign = offStr[0];
            offStr.erase(offStr.begin());
            errno = 0;
            char *offEnd = nullptr;
            long long offVal = std::strtoll(offStr.c_str(), &offEnd, 0);
            if (offEnd == offStr.c_str() || *offEnd != '\0') {
                errorOut = "Invalid offset";
                return std::nullopt;
            }
            offset = (sign == '-') ? -offVal : offVal;
        }
        cmd.address = base + static_cast<uintptr_t>(offset);
    }
    if (cmd.type == Command::Type::Patch) {
        std::string tok;
        while (ls >> tok) {
            try {
                uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                cmd.bytes.push_back(b);
            } catch (...) {
                errorOut = "Invalid byte: " + tok;
                return std::nullopt;
            }
        }
        if (cmd.bytes.empty()) {
            errorOut = "No bytes provided";
            return std::nullopt;
        }
    }
    return cmd;
}

std::optional<AutoAssembler::Script> AutoAssembler::parse(const std::string &scriptText,
                                                          std::vector<std::string> &errors,
                                                          std::vector<std::string> *logOut) {
    symbols_.clear();
    auto modules = collectModuleBases();
    symbols_.insert(modules.begin(), modules.end());
    Script script;
    bool inEnable = true;
    std::istringstream iss(scriptText);
    std::string line;
    int lineNo = 0;
    while (std::getline(iss, line)) {
        lineNo++;
        if (line.empty()) continue;
        std::string trimmed = trimCopy(line);
        if (trimmed.empty()) continue;
        if (trimmed == "[ENABLE]" || trimmed == "[enable]") {
            inEnable = true;
            continue;
        }
        if (trimmed == "[DISABLE]" || trimmed == "[disable]") {
            inEnable = false;
            continue;
        }
        if (trimmed.rfind("aobscan", 0) == 0) {
            std::string name;
            std::string module;
            std::string pattern;
            bool moduleVariant = trimmed.rfind("aobscanmodule", 0) == 0;
            auto joinFrom = [](const std::vector<std::string> &parts, size_t start) {
                std::string out;
                for (size_t i = start; i < parts.size(); ++i) {
                    if (!out.empty()) out.push_back(',');
                    out += parts[i];
                }
                return trimCopy(out);
            };
            auto assignArgs = [&](const std::vector<std::string> &parts) {
                if (moduleVariant) {
                    if (parts.size() < 3) return false;
                    name = parts[0];
                    module = parts[1];
                    pattern = joinFrom(parts, 2);
                } else {
                    if (parts.size() < 2) return false;
                    name = parts[0];
                    pattern = joinFrom(parts, 1);
                }
                return true;
            };
            bool parsed = false;
            auto parenPos = trimmed.find('(');
            if (parenPos != std::string::npos) {
                auto endParen = trimmed.find(')', parenPos);
                auto inside = trimmed.substr(parenPos + 1,
                                             endParen == std::string::npos ? std::string::npos : endParen - parenPos - 1);
                std::vector<std::string> parts;
                std::stringstream argStream(inside);
                std::string chunk;
                while (std::getline(argStream, chunk, ',')) {
                    parts.push_back(trimCopy(chunk));
                }
                parsed = assignArgs(parts);
            }
            if (!parsed) {
                std::istringstream ls(trimmed);
                std::string kw;
                ls >> kw;
                ls >> name;
                if (moduleVariant) ls >> module;
                std::string tok;
                while (ls >> tok) {
                    if (!pattern.empty()) pattern.push_back(' ');
                    pattern += tok;
                }
                parsed = !name.empty() && !pattern.empty() && (!moduleVariant || !module.empty());
            }
            pattern = trimCopy(pattern);
            if (moduleVariant) module = trimCopy(module);
            if (moduleVariant) {
                if (module.size() >= 2 && (module.front() == '"' || module.front() == '\'') && module.back() == module.front()) {
                    module = module.substr(1, module.size() - 2);
                }
            }
            if (!parsed) {
                errors.push_back("Line " + std::to_string(lineNo) + ": invalid aobscan syntax");
                continue;
            }
            std::string err;
            auto addrOpt = scanAob(pattern, err, moduleVariant ? module : std::string());
            if (!addrOpt.has_value()) {
                errors.push_back("Line " + std::to_string(lineNo) + ": aobscan failed for " + name + " (" + err + ")");
                continue;
            }
            symbols_[name] = *addrOpt;
            if (logOut) {
                logOut->push_back(std::string(moduleVariant ? "aobscanmodule" : "aobscan") + " " + name +
                                  (moduleVariant ? " [" + module + "]" : "") + " -> " + addrToHex(*addrOpt));
            }
            continue;
        }

        std::string err;
        auto cmdOpt = parseLine(trimmed, symbols_, err);
        if (!cmdOpt) {
            if (!err.empty()) {
                errors.push_back("Line " + std::to_string(lineNo) + ": " + err);
            }
            continue;
        }
        if (inEnable) script.enableCmds.push_back(std::move(*cmdOpt));
        else script.disableCmds.push_back(std::move(*cmdOpt));
    }
    if (script.enableCmds.empty() && script.disableCmds.empty()) {
        std::string err;
        auto single = parseLine(scriptText, symbols_, err);
        if (single) {
            script.enableCmds.push_back(std::move(*single));
        } else if (!err.empty()) {
            errors.push_back(err);
        }
    }
    last_ = script;
    return script;
}

bool AutoAssembler::apply(const CommandList &cmds) {
    for (const auto &cmd : cmds) {
        if (cmd.type == Command::Type::Patch) {
            injector_.patchBytes(cmd.address, cmd.bytes);
        } else if (cmd.type == Command::Type::Restore) {
            injector_.restore(cmd.address);
        }
    }
    return true;
}

bool AutoAssembler::restore(const CommandList &cmds) {
    for (const auto &cmd : cmds) {
        injector_.restore(cmd.address);
    }
    return true;
}

bool AutoAssembler::enableScript(const std::string &scriptText, std::string *logOut) {
    std::vector<std::string> errors;
    std::vector<std::string> logs;
    auto result = parse(ensureEnableSection(scriptText), errors, logOut ? &logs : nullptr);
    if (!errors.empty()) {
        if (logOut) {
            for (size_t i = 0; i < errors.size(); ++i) {
                if (i) logOut->push_back('\n');
                *logOut += errors[i];
            }
        }
        return false;
    }
    if (!result.has_value() || (result->enableCmds.empty() && result->disableCmds.empty())) {
        if (logOut) *logOut = "No commands found";
        return false;
    }
    apply(result->enableCmds);
    enabled_ = true;
    if (logOut) {
        for (size_t i = 0; i < logs.size(); ++i) {
            if (i) logOut->push_back('\n');
            *logOut += logs[i];
        }
    }
    return true;
}

bool AutoAssembler::disableScript(std::string *) {
    if (!enabled_) return false;
    if (!last_.disableCmds.empty()) {
        apply(last_.disableCmds);
    } else {
        restore(last_.enableCmds);
    }
    enabled_ = false;
    return true;
}

std::optional<uintptr_t> AutoAssembler::scanAob(const std::string &pattern, std::string &errorOut,
                                                const std::string &moduleFilter) const {
    const auto &proc = injector_.target();
    if (!proc.isAttached()) {
        errorOut = "Not attached";
        return std::nullopt;
    }
    std::string filter = trimCopy(moduleFilter);
    std::string loweredFilter = toLower(filter);
    bool filterAll = loweredFilter.empty() || loweredFilter == "$process";

    auto moduleMatches = [&](const MemoryRegion &region) {
        if (filterAll) return true;
        if (region.path.empty()) return false;
        std::string pathLower = toLower(region.path);
        if (pathLower == loweredFilter) return true;
        std::string base = region.path;
        auto slash = base.find_last_of("/\\");
        if (slash != std::string::npos) base = base.substr(slash + 1);
        return toLower(base) == loweredFilter;
    };

    std::vector<int> pat;
    {
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok) {
            if (tok == "??" || tok == "?" || tok == "**") {
                pat.push_back(-1);
            } else {
                try {
                    int v = std::stoi(tok, nullptr, 16);
                    pat.push_back(v & 0xFF);
                } catch (...) {
                    errorOut = "Bad pattern byte: " + tok;
                    return std::nullopt;
                }
            }
        }
    }
    if (pat.empty()) {
        errorOut = "Empty pattern";
        return std::nullopt;
    }
    constexpr size_t kChunk = 64 * 1024;
    std::vector<unsigned char> buffer(kChunk + pat.size());
    for (const auto &region : proc.regions()) {
        if (region.perms.find('r') == std::string::npos) continue;
        if (!moduleMatches(region)) continue;
        auto start = region.start;
        auto end = region.end;
        for (uintptr_t addr = start; addr < end; addr += kChunk) {
            size_t toRead = std::min(kChunk, end - addr);
            buffer.resize(toRead + pat.size());
            if (!proc.readMemory(addr, buffer.data(), toRead)) continue;
            size_t limit = toRead >= pat.size() ? toRead - pat.size() + 1 : 0;
            for (size_t i = 0; i < limit; ++i) {
                bool match = true;
                for (size_t j = 0; j < pat.size(); ++j) {
                    int p = pat[j];
                    if (p == -1) continue;
                    if (buffer[i + j] != static_cast<unsigned char>(p)) { match = false; break; }
                }
                if (match) {
                    return addr + i;
                }
            }
        }
    }
    errorOut = "Pattern not found";
    return std::nullopt;
}

bool AutoAssembler::resolveOperand(const std::string &addrStr, uintptr_t &outAddr, std::string &errorOut) const {
    std::string err;
    auto cmd = parseLine("patch " + addrStr + " 00", symbols_, err);
    if (!cmd) {
        errorOut = err;
        return false;
    }
    outAddr = cmd->address;
    return true;
}

std::unordered_map<std::string, uintptr_t> AutoAssembler::collectModuleBases() const {
    std::unordered_map<std::string, uintptr_t> mods;
    const auto &proc = injector_.target();
    if (!proc.isAttached()) return mods;
    for (const auto &r : proc.regions()) {
        if (r.path.empty()) continue;
        auto pos = r.path.find_last_of('/');
        std::string name = (pos == std::string::npos) ? r.path : r.path.substr(pos + 1);
        if (mods.find(name) == mods.end()) {
            mods[name] = r.start;
        }
    }
    return mods;
}

std::string AutoAssembler::ensureEnableSection(const std::string &scriptText) {
    std::string script = trimCopy(scriptText);
    if (script.empty()) return script;
    std::string lowered = toLower(script);
    if (lowered.find("[enable]") == std::string::npos) {
        script = "[ENABLE]\n" + script + "\n\n[DISABLE]\n";
    }
    return script;
}

std::string AutoAssembler::joinBytesHex(const std::vector<uint8_t> &bytes) {
    std::string out;
    for (uint8_t b : bytes) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", b);
        if (!out.empty()) out.push_back(' ');
        out += buf;
    }
    return out;
}

std::string AutoAssembler::codeInjectionTemplate(uintptr_t address, const std::vector<uint8_t> &originalBytes) {
    std::string addrStr = addrToHex(address);
    std::string lines;
    lines += "[ENABLE]\n";
    lines += "patch " + addrStr + " 90 90 90 90 90\n";
    lines += "; original " + joinBytesHex(originalBytes) + "\n";
    lines += "\n[DISABLE]\n";
    lines += "restore " + addrStr + "\n";
    return lines;
}

std::string AutoAssembler::aobInjectionTemplate(const std::vector<uint8_t> &patternBytes) {
    std::string pattern = joinBytesHex(patternBytes);
    std::string lines;
    lines += "[ENABLE]\n";
    lines += "aobscanmodule(INJECT,$process," + pattern + ")\n";
    lines += "patch INJECT 90 90 90 90 90\n";
    lines += "; original " + pattern + "\n";
    lines += "\n[DISABLE]\n";
    lines += "restore INJECT\n";
    return lines;
}

std::string AutoAssembler::emptyTemplate() {
    return "[ENABLE]\n\n[DISABLE]\n";
}

std::string AutoAssembler::patchScript(uintptr_t address, const std::vector<uint8_t> &patchBytes, bool viaAob,
                                       const std::vector<uint8_t> *originalBytes) {
    if (address == 0) return std::string();
    std::string patchLine = patchBytes.empty() ? "90 90 90 90 90" : joinBytesHex(patchBytes);
    std::string original = originalBytes ? joinBytesHex(*originalBytes) : std::string();
    std::string addrStr = addrToHex(address);
    std::string lines;
    lines += "[ENABLE]\n";
    if (viaAob) {
        std::string pattern = original.empty() ? patchLine : original;
        lines += "aobscanmodule(INJECT,$process," + pattern + ")\n";
        lines += "patch INJECT " + patchLine + "\n";
    } else {
        lines += "patch " + addrStr + " " + patchLine + "\n";
    }
    if (!original.empty()) {
        lines += "; original " + original + "\n";
    }
    lines += "\n[DISABLE]\n";
    lines += viaAob ? "restore INJECT\n" : ("restore " + addrStr + "\n");
    return lines;
}

} // namespace core
