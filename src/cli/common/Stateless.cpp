#include "Cli.h"
#include "PatchStore.h"

#include "core/AutoAssembler.h"
#include "core/CodeInjector.h"
#include "core/MemoryScanner.h"
#include "core/PointerScanner.h"
#include "core/ProcessEnumerator.h"
#include "core/Disassembler.h"
#include "core/ScalarCodec.h"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace cli {

namespace {

int requireProc(CmdCtx &ctx) {
    if (!ctx.proc || !ctx.proc->isAttached()) {
        return fail(ctx, kExitNotAttached, "not_attached", "no target process (use --pid or comfy attach)");
    }
    return kExitOk;
}


std::vector<uint8_t> readBytesOrErr(CmdCtx &ctx, uintptr_t addr, size_t len) {
    std::vector<uint8_t> buf(len);
    if (!ctx.proc->readMemory(addr, buf.data(), buf.size())) {
        fail(ctx, kExitInvalidValue, "read_failed", "failed to read " + std::to_string(len) + " bytes at " + addrHex(addr));
        return {};
    }
    return buf;
}

int cmdPs(CmdCtx &ctx, Tokens &) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &p : core::ProcessEnumerator::list()) {
        arr.push_back({{"pid", p.pid}, {"name", p.name}, {"cmdline", p.cmdline}});
    }
    if (ctx.out.json) {
        ctx.out.setJson(arr);
    } else {
        ctx.out.line("PID      NAME");
        for (const auto &p : core::ProcessEnumerator::list()) {
            char row[512];
            snprintf(row, sizeof(row), "%-8d %s", static_cast<int>(p.pid), p.name.c_str());
            ctx.out.line(row);
        }
    }
    return kExitOk;
}

int cmdRegions(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    std::string permFilter = t.value("--perm").value_or("");
    std::string pathFilter = t.value("--path").value_or("");
    long long limit = t.intValue("--limit").value_or(500);
    long long offset = t.intValue("--offset").value_or(0);

    auto regions = ctx.proc->regions();
    std::vector<const core::MemoryRegion *> filtered;
    for (const auto &r : regions) {
        if (!permFilter.empty() && r.perms.find(permFilter) == std::string::npos) continue;
        if (!pathFilter.empty() && r.path.find(pathFilter) == std::string::npos) continue;
        filtered.push_back(&r);
    }
    long long total = static_cast<long long>(filtered.size());
    nlohmann::json arr = nlohmann::json::array();
    long long shown = 0;
    for (long long i = offset; i < total && shown < limit; ++i, ++shown) {
        const auto *r = filtered[static_cast<size_t>(i)];
        arr.push_back({{"start", addrHex(r->start)},
                       {"end", addrHex(r->end)},
                       {"size", static_cast<uint64_t>(r->end - r->start)},
                       {"perms", r->perms},
                       {"path", r->path}});
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"total", total}, {"offset", offset}, {"regions", arr}});
    } else {
        for (const auto &r : arr) {
            ctx.out.line(r["start"].get<std::string>() + "-" + r["end"].get<std::string>() + " " +
                         r["perms"].get<std::string>() + " " + r["path"].get<std::string>());
        }
        ctx.out.line(std::to_string(total) + " regions");
    }
    return kExitOk;
}

int cmdModules(CmdCtx &ctx, Tokens &) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    std::map<std::string, uintptr_t> mods;
    for (const auto &r : ctx.proc->regions()) {
        if (r.path.empty()) continue;
        auto pos = r.path.find_last_of('/');
        std::string name = (pos == std::string::npos) ? r.path : r.path.substr(pos + 1);
        auto it = mods.find(name);
        if (it == mods.end() || r.start < it->second) mods[name] = r.start;
    }
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &kv : mods) {
        arr.push_back({{"name", kv.first}, {"base", addrHex(kv.second)}});
    }
    if (ctx.out.json) {
        ctx.out.setJson(arr);
    } else {
        for (const auto &m : arr) {
            ctx.out.line(m["base"].get<std::string>() + " " + m["name"].get<std::string>());
        }
    }
    return kExitOk;
}

int cmdRead(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("read"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    core::ValueType type;
    size_t len = 0;
    bool ptrMode = false;
    if (!parseTypeSpec(pos[1], type, len, err, &ptrMode)) {
        return fail(ctx, kExitUsage, "invalid_type", err);
    }

    std::string valueStr;
    uint64_t raw = 0;
    if (type == core::ValueType::ArrayOfByte || type == core::ValueType::String) {
        auto buf = readBytesOrErr(ctx, *addrOpt, len);
        if (!ctx.err.code.empty()) return ctx.err.exitCode;
        valueStr = core::formatValueBytes(buf.data(), buf.size(), type);
        if (type == core::ValueType::String) valueStr = trimNuls(valueStr);
    } else {
        auto scalar = readBytesOrErr(ctx, *addrOpt, core::sizeForType(type));
        if (!ctx.err.code.empty()) return ctx.err.exitCode;
        std::memcpy(&raw, scalar.data(), scalar.size());
        valueStr = core::formatRawValue(raw, type);
    }
    char rawHexBuf[32];
    snprintf(rawHexBuf, sizeof(rawHexBuf), "0x%016llx", static_cast<unsigned long long>(raw));
    if (ptrMode) valueStr = rawHexBuf;
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)},
                         {"type", core::typeToString(type)},
                         {"value", valueStr},
                         {"raw", raw},
                         {"rawHex", rawHexBuf}});
    } else {
        ctx.out.line(valueStr);
    }
    return kExitOk;
}

int cmdWrite(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 3) return usageError(ctx, *findSpec("write"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    core::ValueType type;
    size_t ignoredLen = 0;
    bool writePtr = false;
    if (!parseTypeSpec(pos[1], type, ignoredLen, err, &writePtr)) {
        return fail(ctx, kExitUsage, "invalid_type", err);
    }
    if (writePtr) type = core::ValueType::Int64;
    std::string valueStr;
    for (size_t i = 2; i < pos.size(); ++i) {
        if (!valueStr.empty()) valueStr.push_back(' ');
        valueStr += pos[i];
    }
    std::vector<uint8_t> bytes;
    if (type == core::ValueType::ArrayOfByte) {
        bytes = parseHexBytesStr(valueStr);
        if (bytes.empty()) return fail(ctx, kExitInvalidValue, "invalid_value", "bad AOB hex: " + valueStr);
    } else if (type == core::ValueType::String) {
        bytes.assign(valueStr.begin(), valueStr.end());
    } else {
        std::vector<uint8_t> parsed;
        if (writePtr) {
            errno = 0;
            char *end = nullptr;
            unsigned long long pv = std::strtoull(valueStr.c_str(), &end, 0);
            if (end == valueStr.c_str() || *end != '\0') {
                return fail(ctx, kExitInvalidValue, "invalid_value", "cannot parse pointer '" + valueStr + "'");
            }
            parsed.resize(sizeof(pv));
            std::memcpy(parsed.data(), &pv, sizeof(pv));
        } else {
            auto opt = core::parseScalar(valueStr, type);
            if (!opt) return fail(ctx, kExitInvalidValue, "invalid_value", "cannot parse '" + valueStr + "' as " + core::typeToString(type));
            parsed = *opt;
        }
        bytes = parsed;
    }
    bool dryRun = t.has("--dry-run");
    if (!dryRun && !ctx.proc->writeMemory(*addrOpt, bytes.data(), bytes.size())) {
        return fail(ctx, kExitTargetGone, "write_failed", "failed to write at " + addrHex(*addrOpt));
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)},
                         {"written", core::formatValueBytes(bytes.data(), bytes.size(), core::ValueType::ArrayOfByte)},
                         {"dry_run", dryRun}});
    }
    return kExitOk;
}

int cmdHexdump(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("hexdump"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    long long len = t.intValue("--length").value_or(0);
    if (len == 0) {
        try {
            len = std::stoll(pos[1], nullptr, 0);
        } catch (...) {
            return usageError(ctx, *findSpec("hexdump"));
        }
    }
    if (len <= 0 || len > 65536) return fail(ctx, kExitUsage, "invalid_length", "length must be 1..65536");
    auto buf = readBytesOrErr(ctx, *addrOpt, static_cast<size_t>(len));
    if (buf.empty()) return ctx.err.exitCode;

    nlohmann::json rows = nlohmann::json::array();
    std::ostringstream text;
    const size_t width = 16;
    for (size_t i = 0; i < buf.size(); i += width) {
        char head[32];
        snprintf(head, sizeof(head), "%016llx  ", static_cast<unsigned long long>(*addrOpt + i));
        std::string hexPart, asciiPart;
        for (size_t j = 0; j < width; ++j) {
            if (i + j < buf.size()) {
                uint8_t b = buf[i + j];
                char cell[4];
                snprintf(cell, sizeof(cell), "%02x ", b);
                hexPart += cell;
                asciiPart += (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
            } else {
                hexPart += "   ";
                asciiPart += ' ';
            }
        }
        if (ctx.out.json) {
            std::string compactHex;
            for (size_t j = i; j < buf.size() && j < i + width; ++j) {
                char c[3];
                snprintf(c, sizeof(c), "%02x", buf[j]);
                compactHex += c;
            }
            rows.push_back({{"address", addrHex(*addrOpt + i)},
                            {"hex", compactHex},
                            {"ascii", asciiPart}});
        } else {
            text << head << hexPart << " " << asciiPart << "\n";
        }
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)}, {"length", len}, {"rows", rows}});
    } else {
        ctx.out.line(text.str());
    }
    return kExitOk;
}

int cmdDisasm(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("disasm"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    long long byteCount = t.intValue("--bytes").value_or(128);
    if (byteCount <= 0 || byteCount > 65536) return fail(ctx, kExitUsage, "invalid_length", "--bytes must be 1..65536");
    long long maxInsns = t.intValue("--count").value_or(0);
    auto code = readBytesOrErr(ctx, *addrOpt, static_cast<size_t>(byteCount));
    if (!ctx.err.code.empty()) return ctx.err.exitCode;

    core::Disassembler dis;
    auto insns = dis.valid() ? dis.disassemble(code.data(), code.size(), *addrOpt,
                                               static_cast<size_t>(maxInsns))
                             : std::vector<core::Instruction>{};
    nlohmann::json arr = nlohmann::json::array();
    if (insns.empty()) {
        std::string hex;
        for (uint8_t b : code) {
            char c[4];
            snprintf(c, sizeof(c), "%02x", b);
            if (!hex.empty()) hex.push_back(' ');
            hex += c;
        }
        if (ctx.out.json) {
            ctx.out.setJson({{"address", addrHex(*addrOpt)}, {"disassembled", false}, {"bytes", hex}});
        } else {
            ctx.out.line("db " + hex);
        }
        return kExitOk;
    }
    for (const auto &insn : insns) {
        std::string bytes;
        for (uint8_t b : insn.bytes) {
            char c[4];
            snprintf(c, sizeof(c), "%02x", b);
            if (!bytes.empty()) bytes.push_back(' ');
            bytes += c;
        }
        arr.push_back({{"address", addrHex(insn.address)},
                       {"bytes", bytes},
                       {"mnemonic", insn.mnemonic},
                       {"operands", insn.operands}});
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)}, {"disassembled", true}, {"instructions", arr}});
    } else {
        for (const auto &i : arr) {
            ctx.out.line(i["address"].get<std::string>() + "  " + i["bytes"].get<std::string>() + "  " +
                         i["mnemonic"].get<std::string>() + " " + i["operands"].get<std::string>());
        }
    }
    return kExitOk;
}

int doPatch(CmdCtx &ctx, uintptr_t addr, const std::vector<uint8_t> &bytes) {
    PatchRecord rec;
    rec.pid = ctx.proc->pid();
    rec.address = addr;
    rec.original.resize(bytes.size());
    if (!ctx.proc->readMemory(addr, rec.original.data(), rec.original.size())) {
        return fail(ctx, kExitInvalidValue, "read_failed", "cannot read original bytes at " + addrHex(addr));
    }
    if (!ctx.proc->writeMemory(addr, bytes.data(), bytes.size())) {
        return fail(ctx, kExitTargetGone, "write_failed", "failed to write at " + addrHex(addr));
    }
    PatchStore store(cacheDir() + "/patches.json");
    store.put(rec);
    return kExitOk;
}

int cmdPatch(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("patch"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    std::string hexStr;
    for (size_t i = 1; i < pos.size(); ++i) {
        if (!hexStr.empty()) hexStr.push_back(' ');
        hexStr += pos[i];
    }
    auto bytes = parseHexBytesStr(hexStr);
    if (bytes.empty()) return fail(ctx, kExitInvalidValue, "invalid_value", "bad hex bytes: " + hexStr);
    bool dryRun = t.has("--dry-run");
    if (dryRun) {
        if (ctx.out.json) {
            ctx.out.setJson({{"address", addrHex(*addrOpt)}, {"dry_run", true},
                             {"bytes", core::AutoAssembler::joinBytesHex(bytes)}});
        }
        return kExitOk;
    }
    int rc2 = doPatch(ctx, *addrOpt, bytes);
    if (rc2 != kExitOk) return rc2;
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)},
                         {"patched", core::AutoAssembler::joinBytesHex(bytes)},
                         {"restorable", true}});
    }
    return kExitOk;
}

int cmdUnpatch(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("unpatch"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    PatchStore store(cacheDir() + "/patches.json");
    PatchRecord rec;
    if (ctx.injector && ctx.injector->patches().count(*addrOpt)) {
        if (!ctx.injector->restore(*addrOpt)) {
            return fail(ctx, kExitGeneric, "restore_failed", "injector restore failed at " + addrHex(*addrOpt));
        }
    } else if (store.get(ctx.proc->pid(), *addrOpt, rec)) {
        if (!ctx.proc->writeMemory(*addrOpt, rec.original.data(), rec.original.size())) {
            return fail(ctx, kExitTargetGone, "write_failed", "failed to write at " + addrHex(*addrOpt));
        }
    } else {
        return fail(ctx, kExitNoTarget, "no_patch", "no recorded patch at " + addrHex(*addrOpt));
    }
    store.remove(ctx.proc->pid(), *addrOpt);
    if (ctx.out.json) {
        ctx.out.setJson({{"address", addrHex(*addrOpt)}, {"restored", true}});
    }
    return kExitOk;
}

int cmdPatches(CmdCtx &ctx, Tokens &t) {
    PatchStore store(cacheDir() + "/patches.json");
    pid_t pid = t.intValue("--pid").value_or(0);
    auto records = store.list(pid);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &r : records) {
        arr.push_back({{"pid", r.pid},
                       {"address", addrHex(r.address)},
                       {"original", core::AutoAssembler::joinBytesHex(r.original)}});
    }
    if (ctx.out.json) {
        ctx.out.setJson(arr);
    } else {
        for (const auto &r : arr) {
            ctx.out.line("pid=" + std::to_string(r["pid"].get<long long>()) + " " +
                         r["address"].get<std::string>() + " original: " +
                         r["original"].get<std::string>());
        }
    }
    return kExitOk;
}

int cmdNop(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("nop"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    long long len = 0;
    try {
        len = std::stoll(pos[1], nullptr, 0);
    } catch (...) {
        return usageError(ctx, *findSpec("nop"));
    }
    if (len <= 0 || len > 4096) return fail(ctx, kExitUsage, "invalid_length", "nop length must be 1..4096");
    return doPatch(ctx, *addrOpt, std::vector<uint8_t>(static_cast<size_t>(len), 0x90));
}

int cmdPscan(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("pscan"));
    std::string err;
    auto targetOpt = resolveAddrExpr(*ctx.proc, pos[0], err);
    if (!targetOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    long long maxOffset = t.intValue("--max-offset").value_or(4096);
    if (maxOffset <= 0) return fail(ctx, kExitUsage, "invalid_value", "--max-offset must be > 0");
    bool writableOnly = t.has("--writable-only");
    long long limit = t.intValue("--limit").value_or(50);

    core::PointerScanner scanner(*ctx.proc);
    auto hits = scanner.scan(*targetOpt, maxOffset, writableOnly);
    long long total = static_cast<long long>(hits.size());
    nlohmann::json arr = nlohmann::json::array();
    for (long long i = 0; i < total && i < limit; ++i) {
        arr.push_back({{"base", addrHex(hits[static_cast<size_t>(i)].baseAddress)},
                       {"offset", hits[static_cast<size_t>(i)].offset},
                       {"final", addrHex(hits[static_cast<size_t>(i)].finalAddress)}});
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"target", addrHex(*targetOpt)}, {"total", total}, {"hits", arr}});
    } else {
        for (const auto &h : arr) {
            ctx.out.line("base=" + h["base"].get<std::string>() + " offset=" +
                         h["offset"].dump() + " final=" + h["final"].get<std::string>());
        }
        ctx.out.line(std::to_string(total) + " hits");
    }
    return kExitOk;
}

int cmdAobReplace(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("aob-replace"));
    std::string pattern = pos[0];
    std::string replStr;
    for (size_t i = 1; i < pos.size(); ++i) {
        if (!replStr.empty()) replStr.push_back(' ');
        replStr += pos[i];
    }
    auto replacement = parseHexBytesStr(replStr);
    if (replacement.empty()) return fail(ctx, kExitInvalidValue, "invalid_value", "bad replacement bytes: " + replStr);
    long long limit = t.intValue("--limit").value_or(100);

    std::vector<int> pat;
    {
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok) {
            if (tok == "??" || tok == "?" || tok == "**") {
                pat.push_back(-1);
            } else {
                try {
                    pat.push_back(std::stoi(tok, nullptr, 16) & 0xFF);
                } catch (...) {
                    return fail(ctx, kExitInvalidValue, "invalid_pattern", "bad pattern byte: " + tok);
                }
            }
        }
    }
    if (pat.empty()) return fail(ctx, kExitInvalidValue, "invalid_pattern", "empty pattern");

    core::ScanParams params;
    params.type = core::ValueType::ArrayOfByte;
    params.mode = core::ScanMode::Aob;
    params.value1 = pattern;
    params.skipMaskedRegions = true;
    core::MemoryScanner scanner(*ctx.proc);
    if (!scanner.firstScan(params)) {
        return fail(ctx, kExitGeneric, "scan_failed", "aob scan failed (pattern not found)");
    }
    const auto &results = scanner.results();
    nlohmann::json patched = nlohmann::json::array();
    long long applied = 0;
    for (const auto &r : results) {
        if (applied >= limit) break;
        std::vector<uint8_t> verify(replacement.size());
        if (!ctx.proc->readMemory(r.address, verify.data(), verify.size())) continue;
        bool match = true;
        for (size_t j = 0; j < verify.size(); ++j) {
            if (pat[j] != -1 && verify[j] != static_cast<uint8_t>(pat[j])) { match = false; break; }
        }
        if (!match) continue;
        if (!ctx.proc->writeMemory(r.address, replacement.data(), replacement.size())) continue;
        PatchStore store(cacheDir() + "/patches.json");
        PatchRecord rec;
        rec.pid = ctx.proc->pid();
        rec.address = r.address;
        rec.original = verify;
        store.put(rec);
        patched.push_back(addrHex(r.address));
        ++applied;
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"matches", results.size()}, {"patched", patched}, {"count", applied}});
    } else {
        ctx.out.line("patched " + std::to_string(applied) + " of " +
                     std::to_string(results.size()) + " matches");
    }
    return kExitOk;
}

int cmdAaRun(CmdCtx &ctx, Tokens &t) {
    int rc = requireProc(ctx);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("aa-run"));
    if (!ctx.injector) {
        return fail(ctx, kExitNotAttached, "no_injector", "internal error: injector unavailable");
    }
    std::ifstream f(pos[0]);
    if (!f.good()) return fail(ctx, kExitFileIo, "file_io", "cannot open script file: " + pos[0]);
    std::stringstream ss;
    ss << f.rdbuf();
    std::string scriptText = ss.str();

    std::string section = t.value("--section").value_or("enable");
    core::CodeInjector inj(*ctx.proc);
    core::AutoAssembler runner(inj);
    std::vector<std::string> errors;
    auto parsed = runner.parse(core::AutoAssembler::ensureEnableSection(scriptText), errors);
    if (!errors.empty()) {
        std::string joined;
        for (const auto &e : errors) {
            if (!joined.empty()) joined.push_back('\n');
            joined += e;
        }
        return fail(ctx, kExitInvalidValue, "parse_error", joined);
    }
    if (!parsed) return fail(ctx, kExitInvalidValue, "parse_error", "empty script");

    std::string log;
    if (section == "enable") {
        runner.apply(parsed->enableCmds);
        log = "enabled";
    } else if (section == "disable") {
        if (!parsed->disableCmds.empty()) {
            runner.apply(parsed->disableCmds);
        } else {
            PatchStore store(cacheDir() + "/patches.json");
            for (const auto &cmd : parsed->enableCmds) {
                PatchRecord rec;
                if (store.get(ctx.proc->pid(), cmd.address, rec)) {
                    ctx.proc->writeMemory(cmd.address, rec.original.data(), rec.original.size());
                } else if (ctx.injector && ctx.injector->patches().count(cmd.address)) {
                    ctx.injector->restore(cmd.address);
                }
            }
        }
        log = "disabled";
    } else {
        return fail(ctx, kExitUsage, "invalid_section", "--section must be enable or disable");
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"script", pos[0]}, {"section", section}, {"result", log}});
    } else {
        ctx.out.line(log);
    }
    return kExitOk;
}

} // namespace

void registerStatelessCommands(std::vector<CmdSpec> &cmds) {
    cmds.push_back({"ps", "", "list processes", false, cmdPs});
    cmds.push_back({"regions", "[--perm RWX] [--path SUB] [--limit N] [--offset N]",
                    "list memory regions of the target", false, cmdRegions});
    cmds.push_back({"modules", "", "list loaded modules with base addresses", false, cmdModules});
    cmds.push_back({"read", "<addr> <type[@len]>",
                    "read a value (types: byte,i16,i32,i64,float,double,aob@N,string@N)", false, cmdRead});
    cmds.push_back({"write", "<addr> <type> <value>", "write a typed value (--dry-run supported)", false, cmdWrite});
    cmds.push_back({"hexdump", "<addr> <len>", "classic hex dump of memory", false, cmdHexdump});
    cmds.push_back({"disasm", "<addr> [--bytes N] [--count N]", "disassemble memory (capstone x86-64)", false, cmdDisasm});
    cmds.push_back({"patch", "<addr> <hexbytes...>", "patch bytes (undoable via unpatch)", false, cmdPatch});
    cmds.push_back({"unpatch", "<addr>", "restore original bytes recorded by patch/nop", false, cmdUnpatch});
    cmds.push_back({"patches", "[--pid P]", "list recorded patches", false, cmdPatches});
    cmds.push_back({"nop", "<addr> <len>", "replace bytes with NOPs (recorded)", false, cmdNop});
    cmds.push_back({"pscan", "<addr> --max-offset N [--writable-only]", "single-level pointer scan", false, cmdPscan});
    cmds.push_back({"aob-replace", "<pattern> <hexbytes...> [--limit N]", "verify-then-patch all AoB matches", false, cmdAobReplace});
    cmds.push_back({"aa-run", "<file> [--section enable|disable]", "run an Auto Assembler script", false, cmdAaRun});
}

} // namespace cli
