#include "Cli.h"
#include "PatchStore.h"

#include "core/ScalarCodec.h"
#include "core/TargetProcess.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <sys/stat.h>
#include <unistd.h>

namespace cli {

const std::vector<CmdSpec> &registry() {
    static std::vector<CmdSpec> cmds = [] {
        std::vector<CmdSpec> v;
        registerStatelessCommands(v);
        registerSessionCommands(v);
        return v;
    }();
    return cmds;
}

std::vector<std::string> Tokens::positionals() const {
    std::vector<std::string> out;
    for (size_t i = 0; i < tokens_.size(); ++i) {
        const std::string &t = tokens_[i];
        if (t.rfind("--", 0) == 0) {
            auto eq = t.find('=');
            if (eq == std::string::npos) ++i;
            continue;
        }
        out.push_back(t);
    }
    return out;
}

bool Tokens::has(const std::string &flag) const {
    for (const auto &t : tokens_) {
        if (t == flag) return true;
        if (t.rfind(flag + "=", 0) == 0) return true;
    }
    return false;
}

std::optional<std::string> Tokens::value(const std::string &flag) const {
    std::string prefix = flag + "=";
    for (size_t i = 0; i < tokens_.size(); ++i) {
        const std::string &t = tokens_[i];
        if (t.rfind(prefix, 0) == 0) return t.substr(prefix.size());
        if (t == flag && i + 1 < tokens_.size()) return tokens_[i + 1];
    }
    return std::nullopt;
}

std::optional<long long> Tokens::intValue(const std::string &flag) const {
    auto v = value(flag);
    if (!v) return std::nullopt;
    try {
        size_t pos = 0;
        long long n = std::stoll(*v, &pos, 0);
        while (pos < v->size() && isspace(static_cast<unsigned char>((*v)[pos]))) ++pos;
        if (pos != v->size()) return std::nullopt;
        return n;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<double> Tokens::doubleValue(const std::string &flag) const {
    auto v = value(flag);
    if (!v) return std::nullopt;
    try {
        size_t pos = 0;
        double d = std::stod(*v, &pos);
        while (pos < v->size() && isspace(static_cast<unsigned char>((*v)[pos]))) ++pos;
        if (pos != v->size()) return std::nullopt;
        return d;
    } catch (...) {
        return std::nullopt;
    }
}

int fail(CmdCtx &ctx, int exitCode, std::string code, std::string message, std::string hint) {
    ctx.err.exitCode = exitCode;
    ctx.err.code = std::move(code);
    ctx.err.message = std::move(message);
    ctx.err.hint = std::move(hint);
    return ctx.err.exitCode;
}

int usageError(CmdCtx &ctx, const CmdSpec &spec) {
    return fail(ctx, kExitUsage, "usage", std::string("usage: ") + spec.name + " " + spec.usage);
}

const CmdSpec *findSpec(const std::string &name) {
    for (const auto &c : registry()) {
        if (name == c.name) return &c;
    }
    return nullptr;
}

bool parseTypeSpec(const std::string &spec, core::ValueType &type, size_t &len, std::string &err) {
    std::string base = spec;
    len = 0;
    auto at = spec.find('@');
    if (at != std::string::npos) {
        base = spec.substr(0, at);
        try {
            len = std::stoul(spec.substr(at + 1));
        } catch (...) {
            err = "invalid length in type spec: " + spec;
            return false;
        }
    }
    if (base == "byte" || base == "1") type = core::ValueType::Byte;
    else if (base == "i16" || base == "2") type = core::ValueType::Int16;
    else if (base == "i32" || base == "4" || base == "int") type = core::ValueType::Int32;
    else if (base == "i64" || base == "8" || base == "long") type = core::ValueType::Int64;
    else if (base == "float" || base == "f32") type = core::ValueType::Float;
    else if (base == "double" || base == "f64") type = core::ValueType::Double;
    else if (base == "aob" || base == "bytes") type = core::ValueType::ArrayOfByte;
    else if (base == "string" || base == "str") type = core::ValueType::String;
    else {
        err = "unknown type: " + base;
        return false;
    }
    if ((type == core::ValueType::ArrayOfByte || type == core::ValueType::String) && len == 0) len = 16;
    return true;
}

std::string trimNuls(const std::string &s) {
    size_t cut = s.find('\0');
    return cut == std::string::npos ? s : s.substr(0, cut);
}

std::string cacheDir() {
    const char *xdg = getenv("XDG_CACHE_HOME");
    std::string base = xdg && *xdg ? xdg : std::string(getenv("HOME") ? getenv("HOME") : "/tmp") + "/.cache";
    std::string dir = base + "/comfyengine";
    mkdir(base.c_str(), 0700);
    mkdir(dir.c_str(), 0700);
    return dir;
}

std::string addrHex(uintptr_t a) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(a));
    return buf;
}

std::vector<uint8_t> parseHexBytesStr(const std::string &s) {
    std::vector<uint8_t> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        try {
            out.push_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
        } catch (...) {
            return {};
        }
    }
    return out;
}

static std::unordered_map<std::string, uintptr_t> moduleBases(core::TargetProcess &proc) {
    std::unordered_map<std::string, uintptr_t> mods;
    for (const auto &r : proc.regions()) {
        if (r.path.empty()) continue;
        auto pos = r.path.find_last_of('/');
        std::string name = (pos == std::string::npos) ? r.path : r.path.substr(pos + 1);
        if (mods.find(name) == mods.end()) mods[name] = r.start;
    }
    return mods;
}

std::optional<uintptr_t> resolveAddrExpr(core::TargetProcess &proc, const std::string &expr, std::string &errOut) {
    if (expr.empty()) {
        errOut = "empty address expression";
        return std::nullopt;
    }

    if (expr[0] == '[') {
        size_t close = expr.find(']');
        if (close == std::string::npos) {
            errOut = "unterminated pointer chain bracket";
            return std::nullopt;
        }
        std::string baseStr = expr.substr(1, close - 1);
        auto baseOpt = resolveAddrExpr(proc, baseStr, errOut);
        if (!baseOpt) return std::nullopt;
        uintptr_t current = *baseOpt;
        size_t i = close + 1;
        while (i < expr.size()) {
            if (expr[i] != '+') {
                errOut = "expected +offset in pointer chain at position " + std::to_string(i);
                return std::nullopt;
            }
            size_t j = i + 1;
            while (j < expr.size() && expr[j] != ']') ++j;
            bool hadClose = j < expr.size();
            std::string offStr = expr.substr(i + 1, (hadClose ? j : expr.size()) - i - 1);
            errno = 0;
            char *end = nullptr;
            long long off = std::strtoll(offStr.c_str(), &end, 0);
            if (offStr.empty() || end == offStr.c_str() || *end != '\0') {
                errOut = "invalid pointer chain offset: " + offStr;
                return std::nullopt;
            }
            uintptr_t pointed = 0;
            if (!proc.readMemory(current, &pointed, sizeof(pointed))) {
                errOut = "failed to read pointer at " + addrHex(current);
                return std::nullopt;
            }
            current = pointed + static_cast<uintptr_t>(off);
            i = hadClose ? j + 1 : j;
        }
        return current;
    }

    errno = 0;
    char *end = nullptr;
    unsigned long long literal = std::strtoull(expr.c_str(), &end, 0);
    if (end != expr.c_str() && *end == '\0') {
        return static_cast<uintptr_t>(literal);
    }

    size_t posPlus = expr.find('+');
    size_t posMinus = expr.find('-', 1);
    size_t pos = std::min(posPlus == std::string::npos ? expr.size() : posPlus,
                          posMinus == std::string::npos ? expr.size() : posMinus);
    std::string name = expr.substr(0, pos);
    static bool cached = false;
    static std::unordered_map<std::string, uintptr_t> cachedMods;
    static pid_t cachedPid = -1;
    if (!cached || cachedPid != proc.pid()) {
        cachedMods = moduleBases(proc);
        cachedPid = proc.pid();
        cached = true;
    }
    auto it = cachedMods.find(name);
    if (it == cachedMods.end()) {
        errOut = "unknown symbol or invalid address: " + name;
        return std::nullopt;
    }
    uintptr_t base = it->second;
    int64_t offset = 0;
    if (pos < expr.size()) {
        std::string offStr = expr.substr(pos);
        char sign = offStr[0];
        offStr.erase(offStr.begin());
        errno = 0;
        char *offEnd = nullptr;
        long long offVal = std::strtoll(offStr.c_str(), &offEnd, 0);
        if (offEnd == offStr.c_str() || *offEnd != '\0') {
            errOut = "invalid offset in expression: " + expr;
            return std::nullopt;
        }
        offset = (sign == '-') ? -offVal : offVal;
    }
    return base + static_cast<uintptr_t>(offset);
}

} // namespace cli
