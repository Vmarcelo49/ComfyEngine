#include "Sessions.h"
#include "../common/Cli.h"
#include "../common/PatchStore.h"

#include "core/ProcessEnumerator.h"
#include "core/ScalarCodec.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace cli {

namespace core_ns = core;

namespace {

TargetSession *getSession(CmdCtx &ctx) {
    if (!ctx.mgr) return nullptr;
    return ctx.mgr->get(ctx.sessionName);
}

int requireSession(CmdCtx &ctx, TargetSession **out) {
    TargetSession *s = getSession(ctx);
    if (!s || !s->target || !s->target->isAttached()) {
        return fail(ctx, kExitNotAttached, "not_attached",
                    "no active session '" + ctx.sessionName + "' (run: comfy attach <pid|name>)");
    }
    *out = s;
    return kExitOk;
}

bool writeLineFd(int fd, const std::string &line) {
    if (fd < 0) return false;
    std::string data = line + "\n";
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

std::string joinRest(const std::vector<std::string> &pos, size_t from) {
    std::string out;
    for (size_t i = from; i < pos.size(); ++i) {
        if (!out.empty()) out.push_back(' ');
        out += pos[i];
    }
    return out;
}

nlohmann::json entryToJson(TargetSession &s, const core_ns::CheatEntry &e, bool withValue) {
    nlohmann::json j = {{"index", 0},
                        {"address", addrHex(e.address)},
                        {"type", core_ns::typeToString(e.type)},
                        {"description", e.description},
                        {"pointer", e.isPointer},
                        {"frozen", e.frozen},
                        {"isScript", e.isScript},
                        {"scriptActive", e.scriptActive}};
    if (e.isPointer && !e.offsets.empty()) {
        j["offsets"] = e.offsets;
    }
    if (withValue && !e.isScript) {
        uintptr_t effective = e.address;
        if (e.isPointer && !e.offsets.empty()) {
            effective = core_ns::resolvePointerChain(*s.target, e.address, e.offsets);
        }
        std::string valueStr = "??";
        if (effective != 0) {
            std::vector<uint8_t> buf;
            if (core_ns::readScalar(*s.target, effective, e.type, buf)) {
                valueStr = trimNuls(core_ns::formatValueBytes(buf.data(), buf.size(), e.type));
                if (!e.frozen) {
                    s.liveValues[e.address] = 0;
                }
            } else {
                valueStr = "??";
            }
        }
        j["value"] = valueStr;
    }
    return j;
}


void restoreAddress(TargetSession &s, uintptr_t address) {
    if (s.injector->patches().count(address)) {
        s.injector->restore(address);
        return;
    }
    PatchStore store(cacheDir() + "/patches.json");
    PatchRecord rec;
    if (store.get(s.pid, address, rec)) {
        s.target->writeMemory(address, rec.original.data(), rec.original.size());
        return;
    }
    s.injector->restore(address);
}

void restoreEnableCmds(TargetSession &s, const core_ns::AutoAssembler::CommandList &cmds) {
    for (const auto &cmd : cmds) {
        restoreAddress(s, cmd.address);
    }
}

void applyDisableSection(TargetSession &s, const core_ns::AutoAssembler::Script &script) {
    const auto &cmds = !script.disableCmds.empty() ? script.disableCmds : script.enableCmds;
    bool hasExplicitDisable = !script.disableCmds.empty();
    for (const auto &cmd : cmds) {
        if (hasExplicitDisable && cmd.type == core_ns::AutoAssembler::Command::Type::Patch) {
            s.injector->patchBytes(cmd.address, cmd.bytes);
            continue;
        }
        restoreAddress(s, cmd.address);
    }
}

int cmdAttach(CmdCtx &ctx, Tokens &t) {
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("attach"));
    ctx.sessionName = t.value("--session").value_or("default");
    pid_t pid = 0;
    std::string procName;
    try {
        unsigned long long v = std::stoull(pos[0], nullptr, 10);
        pid = static_cast<pid_t>(v);
    } catch (...) {
        pid_t self = getpid();
        const core_ns::ProcessInfo *exact = nullptr;
        const core_ns::ProcessInfo *byName = nullptr;
        const core_ns::ProcessInfo *byCmdline = nullptr;
        size_t nameMatches = 0;
        for (const auto &p : core_ns::ProcessEnumerator::list()) {
            if (p.pid == self || p.pid <= 0) continue;
            if (p.name == pos[0]) {
                if (!exact || p.pid > exact->pid) exact = &p;
            } else if (p.name.find(pos[0]) != std::string::npos) {
                ++nameMatches;
                if (!byName || p.pid > byName->pid) byName = &p;
            } else if (!byCmdline && p.cmdline.find(pos[0]) != std::string::npos) {
                byCmdline = &p;
            }
        }
        const core_ns::ProcessInfo *best = exact ? exact : (byName ? byName : byCmdline);
        if (!best) {
            return fail(ctx, kExitNoTarget, "process_not_found", "no process matching '" + pos[0] + "'");
        }
        pid = best->pid;
        procName = best->name;
        if (!exact && byName && ctx.out.json) {
            ctx.out.setJson({{"note", "matched by substring; use the exact process name to be precise"},
                             {"alternatives", static_cast<long long>(nameMatches)}});
        }
    }
    if (procName.empty()) {
        for (const auto &p : core_ns::ProcessEnumerator::list()) {
            if (p.pid == pid) {
                procName = p.name;
                break;
            }
        }
    }

    auto &mgr = SessionManager::instance();
    mgr.mutex.lock();
    TargetSession *session = mgr.create(ctx.sessionName, pid, procName);
    mgr.mutex.unlock();
    if (!session) {
        std::string hint = core_ns::ptraceHint();
        return fail(ctx, kExitPtraceDenied, "attach_failed",
                    "cannot attach to pid " + std::to_string(pid), hint);
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"session", ctx.sessionName}, {"pid", pid}, {"process", procName}});
    } else {
        ctx.out.line("attached to " + procName + " (" + std::to_string(pid) + ") as session '" +
                     ctx.sessionName + "'");
    }
    return kExitOk;
}

int cmdDetach(CmdCtx &ctx, Tokens &t) {
    ctx.sessionName = t.value("--session").value_or("default");
    auto &mgr = SessionManager::instance();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(mgr.mutex);
        removed = mgr.destroy(ctx.sessionName);
    }
    if (!removed) return fail(ctx, kExitNoTarget, "no_session", "no session named '" + ctx.sessionName + "'");
    if (ctx.out.json) {
        ctx.out.setJson({{"detached", ctx.sessionName}});
    }
    return kExitOk;
}

int cmdStatus(CmdCtx &ctx, Tokens &) {
    auto &mgr = SessionManager::instance();
    std::lock_guard<std::mutex> lock(mgr.mutex);
    nlohmann::json arr = nlohmann::json::array();
    for (auto *s : mgr.all()) {
        size_t results = s->scanner ? s->scanner->results().size() : 0;
        size_t frozen = 0;
        size_t scriptsActive = 0;
        for (const auto &e : s->cheatTable ? s->cheatTable->snapshot() : std::vector<core_ns::CheatEntry>{}) {
            if (e.isScript) {
                if (e.scriptActive) ++scriptsActive;
            } else if (e.frozen) {
                ++frozen;
            }
        }
        arr.push_back({{"session", s->name},
                       {"pid", s->pid},
                       {"process", s->procName},
                       {"results", results},
                       {"watches", s->cheatTable ? s->cheatTable->size() : 0},
                       {"frozen", frozen},
                       {"scriptsActive", scriptsActive},
                       {"freezePump", s->cheatTable ? s->cheatTable->pumpRunning() : false}});
    }
    if (ctx.out.json) {
        ctx.out.setJson(arr);
    } else {
        for (const auto &s : arr) {
            ctx.out.line(s["session"].get<std::string>() + ": pid=" +
                         std::to_string(s["pid"].get<long long>()) + " " +
                         s["process"].get<std::string>() + " results=" +
                         std::to_string(s["results"].get<long long>()) + " frozen=" +
                         std::to_string(s["frozen"].get<long long>()));
        }
        if (arr.empty()) ctx.out.line("no sessions");
    }
    return kExitOk;
}

int scanFirst(TargetSession &s, CmdCtx &ctx, Tokens &t) {
    core_ns::ScanParams params;
    auto typeStr = t.value("--type").value_or("i32");
    std::string err;
    core_ns::ValueType vt;
    size_t ignoredLen = 0;
    if (!parseTypeSpec(typeStr, vt, ignoredLen, err)) {
        return fail(ctx, kExitUsage, "invalid_type", err);
    }
    params.type = vt;
    s.resultType = vt;
    std::string modeStr = t.value("--mode").value_or("exact");
    static const std::map<std::string, core_ns::ScanMode> modes = {
        {"exact", core_ns::ScanMode::Exact},         {"unknown", core_ns::ScanMode::UnknownInitial},
        {"changed", core_ns::ScanMode::Changed},     {"unchanged", core_ns::ScanMode::Unchanged},
        {"increased", core_ns::ScanMode::Increased}, {"decreased", core_ns::ScanMode::Decreased},
        {"gt", core_ns::ScanMode::GreaterThan},      {"lt", core_ns::ScanMode::LessThan},
        {"between", core_ns::ScanMode::Between},     {"aob", core_ns::ScanMode::Aob}};
    auto mit = modes.find(modeStr);
    if (mit == modes.end()) return fail(ctx, kExitUsage, "invalid_mode", "unknown mode: " + modeStr);
    params.mode = mit->second;
    params.value1 = t.value("--value").value_or("");
    params.value2 = t.value("--value2").value_or("");
    if ((params.mode == core_ns::ScanMode::Exact || params.mode == core_ns::ScanMode::Aob ||
         params.mode == core_ns::ScanMode::GreaterThan || params.mode == core_ns::ScanMode::LessThan ||
         params.mode == core_ns::ScanMode::Between) &&
        params.value1.empty() && params.mode != core_ns::ScanMode::UnknownInitial) {
        return fail(ctx, kExitUsage, "missing_value", "--value is required for this mode");
    }
    params.hexInput = t.has("--hex");
    params.requireWritable = t.has("--writable");
    params.requireExecutable = t.has("--executable");
    params.skipMaskedRegions = !t.has("--include-masked");
    auto align = t.intValue("--align");
    if (align && *align > 0) params.alignment = static_cast<size_t>(*align);

    s.scanHistory.clear();
    s.liveValues.clear();
    bool ok = s.scanner->firstScan(params);
    if (!ok) {
        return fail(ctx, kExitCancelled, "scan_failed",
                    "scan failed (bad value or cancelled)");
    }
    s.scanHistory.push_back(s.scanner->results());
    size_t count = s.scanner->results().size();
    if (ctx.out.json) {
        ctx.out.setJson({{"phase", "first"}, {"count", count}});
    } else {
        ctx.out.line(std::to_string(count) + " result(s)");
    }
    return kExitOk;
}

int scanNext(TargetSession &s, CmdCtx &ctx, Tokens &t) {
    if (s.scanHistory.empty()) {
        return fail(ctx, kExitGeneric, "no_scan", "run 'comfy scan first' before next");
    }
    core_ns::ScanParams params;
    params.type = s.resultType;
    std::string modeStr = t.value("--mode").value_or("exact");
    static const std::map<std::string, core_ns::ScanMode> modes = {
        {"exact", core_ns::ScanMode::Exact},         {"changed", core_ns::ScanMode::Changed},
        {"unchanged", core_ns::ScanMode::Unchanged}, {"increased", core_ns::ScanMode::Increased},
        {"decreased", core_ns::ScanMode::Decreased}, {"gt", core_ns::ScanMode::GreaterThan},
        {"lt", core_ns::ScanMode::LessThan},         {"between", core_ns::ScanMode::Between}};
    auto mit = modes.find(modeStr);
    if (mit == modes.end()) return fail(ctx, kExitUsage, "invalid_mode", "unknown mode: " + modeStr);
    params.mode = mit->second;
    params.value1 = t.value("--value").value_or("");
    params.value2 = t.value("--value2").value_or("");
    if (params.value1.empty() &&
        (params.mode == core_ns::ScanMode::Exact || params.mode == core_ns::ScanMode::GreaterThan ||
         params.mode == core_ns::ScanMode::LessThan || params.mode == core_ns::ScanMode::Between)) {
        return fail(ctx, kExitUsage, "missing_value", "--value is required for this mode");
    }

    bool ok = s.scanner->nextScan(params);
    if (!ok) {
        return fail(ctx, kExitCancelled, "scan_failed", "next scan failed (bad value or cancelled)");
    }
    s.scanHistory.push_back(s.scanner->results());
    if (s.scanHistory.size() > 2) {
        s.scanHistory.erase(s.scanHistory.begin());
    }
    size_t count = s.scanner->results().size();
    if (ctx.out.json) {
        ctx.out.setJson({{"phase", "next"}, {"count", count}, {"undoable", s.scanHistory.size() > 1}});
    } else {
        ctx.out.line(std::to_string(count) + " result(s)");
    }
    return kExitOk;
}

int cmdScan(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("scan"));
    const std::string &sub = pos[0];

    if (sub == "cancel") {
        if (s->scanner) s->scanner->requestCancel();
        return kExitOk;
    }
    if (sub == "first") return scanFirst(*s, ctx, t);
    if (sub == "next") return scanNext(*s, ctx, t);
    if (sub == "undo") {
        if (s->scanHistory.size() <= 1) {
            return fail(ctx, kExitGeneric, "no_undo", "nothing to undo");
        }
        s->scanHistory.pop_back();
        s->scanner->restoreResults(s->scanHistory.back());
        return kExitOk;
    }
    if (sub == "reset") {
        s->scanner->reset();
        s->scanHistory.clear();
        s->liveValues.clear();
        return kExitOk;
    }
    if (sub == "count") {
        size_t count = s->scanner ? s->scanner->results().size() : 0;
        if (ctx.out.json) ctx.out.setJson({{"count", count}});
        else ctx.out.line(std::to_string(count));
        return kExitOk;
    }
    if (sub == "list") {
        if (!s->scanner) return fail(ctx, kExitGeneric, "no_scan", "no scan performed");
        long long limit = t.intValue("--limit").value_or(50);
        long long offset = t.intValue("--offset").value_or(0);
        bool withValues = t.has("--with-values");
        const auto &results = s->scanner->results();
        long long total = static_cast<long long>(results.size());
        nlohmann::json arr = nlohmann::json::array();
        for (long long i = offset; i < total && i - offset < limit; ++i) {
            const auto &r = results[static_cast<size_t>(i)];
            nlohmann::json row = {{"index", i}, {"address", addrHex(r.address)}};
            uint64_t raw = r.raw;
            if (withValues && s->target->isAttached()) {
                std::vector<uint8_t> buf;
                if (core_ns::readScalar(*s->target, r.address, s->resultType, buf)) {
                    std::memcpy(&raw, buf.data(), std::min(buf.size(), sizeof(uint64_t)));
                }
            }
            row["value"] = core_ns::formatRawValue(raw, s->resultType);
            s->liveValues[r.address] = raw;
            arr.push_back(row);
        }
        if (ctx.out.json) {
            ctx.out.setJson({{"total", total}, {"offset", offset}, {"rows", arr}});
        } else {
            for (const auto &r : arr) {
                ctx.out.line(r["address"].get<std::string>() + "  " + r["value"].get<std::string>());
            }
            ctx.out.line(std::to_string(total) + " total");
        }
        return kExitOk;
    }
    return usageError(ctx, *findSpec("scan"));
}

int cmdWatch(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("watch"));
    const std::string &sub = pos[0];
    auto *table = s->cheatTable.get();

    if (sub == "add") {
        if (pos.size() < 2) return usageError(ctx, *findSpec("watch"));
        std::string err;
        auto addrOpt = resolveAddrExpr(*s->target, pos[1], err);
        if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
        std::vector<uint8_t> cur;
        core_ns::ValueType vt = core_ns::ValueType::Int32;
        if (auto ts = t.value("--type")) {
            size_t lenIgnored = 0;
            if (!parseTypeSpec(*ts, vt, lenIgnored, err)) {
                return fail(ctx, kExitUsage, "invalid_type", err);
            }
        }
        core_ns::CheatEntry e;
        e.address = *addrOpt;
        e.type = vt;
        e.description = joinRest(pos, 2);
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            entries.push_back(e);
        });
        s->updateFreezePump();
        if (ctx.out.json) {
            auto all = table->snapshot();
            ctx.out.setJson({{"index", all.empty() ? 0 : static_cast<long long>(all.size() - 1)},
                             {"address", addrHex(*addrOpt)}});
        }
        return kExitOk;
    }
    if (sub == "rm" || sub == "remove" || sub == "delete") {
        long long idx = 0;
        if (pos.size() < 2 || (idx = std::strtoll(pos[1].c_str(), nullptr, 10)) < 0) {
            return usageError(ctx, *findSpec("watch"));
        }
        bool removed = false;
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            if (idx < static_cast<long long>(entries.size())) {
                entries.erase(entries.begin() + idx);
                removed = true;
            }
        });
        if (!removed) return fail(ctx, kExitNoTarget, "bad_index", "watch index out of range");
        s->updateFreezePump();
        return kExitOk;
    }
    if (sub == "set") {
        if (pos.size() < 3) return usageError(ctx, *findSpec("watch"));
        long long idx = std::strtoll(pos[1].c_str(), nullptr, 10);
        std::string valueStr = joinRest(pos, 2);
        std::vector<uint8_t> bytes;
        bool okApply = false;
        uintptr_t targetAddr = 0;
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            if (idx < 0 || idx >= static_cast<long long>(entries.size())) return;
            auto &e = entries[static_cast<size_t>(idx)];
            if (e.isScript) return;
            if (e.isPointer && !e.offsets.empty()) {
                targetAddr = core_ns::resolvePointerChain(*s->target, e.address, e.offsets);
            } else {
                targetAddr = e.address;
            }
            if (targetAddr == 0) return;
            if (core_ns::writeScalarText(*s->target, targetAddr, e.type, valueStr, &bytes)) {
                okApply = true;
                if (!e.frozen) e.stored = bytes;
            }
        });
        if (!okApply) return fail(ctx, kExitInvalidValue, "write_failed", "could not set value");
        if (ctx.out.json) ctx.out.setJson({{"set", true}, {"bytes", bytes.size()}});
        return kExitOk;
    }
    if (sub == "freeze") {
        if (pos.size() < 3) return usageError(ctx, *findSpec("watch"));
        long long idx = std::strtoll(pos[1].c_str(), nullptr, 10);
        bool on = pos[2] == "on" || pos[2] == "true" || pos[2] == "1";
        bool found = false;
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            if (idx >= 0 && idx < static_cast<long long>(entries.size())) {
                auto &e = entries[static_cast<size_t>(idx)];
                if (e.isScript) return;
                e.frozen = on;
                if (on && e.stored.empty()) {
                    std::vector<uint8_t> buf;
                    if (core_ns::readScalar(*s->target, e.address, e.type, buf)) e.stored = buf;
                }
                found = true;
            }
        });
        if (!found) return fail(ctx, kExitNoTarget, "bad_index", "watch index out of range");
        s->updateFreezePump();
        return kExitOk;
    }
    if (sub == "script") {
        if (pos.size() < 3) return usageError(ctx, *findSpec("watch"));
        long long idx = std::strtoll(pos[1].c_str(), nullptr, 10);
        bool on = pos[2] == "on" || pos[2] == "true" || pos[2] == "1";
        std::string scriptText;
        bool wasActive = false;
        bool found = false;
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            if (idx >= 0 && idx < static_cast<long long>(entries.size())) {
                auto &e = entries[static_cast<size_t>(idx)];
                if (!e.isScript) return;
                scriptText = e.scriptSource;
                wasActive = e.scriptActive;
                found = true;
            }
        });
        if (!found) return fail(ctx, kExitNoTarget, "bad_index", "script watch index out of range");
        if (wasActive == on) return kExitOk;
        core_ns::AutoAssembler runner(*s->injector);
        if (on) {
            std::string log;
            if (!runner.enableScript(scriptText, &log)) {
                return fail(ctx, kExitGeneric, "script_failed", log.empty() ? "enable failed" : log);
            }
        } else {
            std::vector<std::string> errors;
            auto parsed = runner.parse(scriptText, errors);
            if (parsed) {
                applyDisableSection(*s, *parsed);
            }
        }
        table->mutate([&](std::vector<core_ns::CheatEntry> &entries) {
            if (idx >= 0 && idx < static_cast<long long>(entries.size())) {
                entries[static_cast<size_t>(idx)].scriptActive = on;
            }
        });
        return kExitOk;
    }
    if (sub == "list") {
        bool withValues = t.has("--with-values");
        auto entries = table->snapshot();
        nlohmann::json arr = nlohmann::json::array();
        for (size_t i = 0; i < entries.size(); ++i) {
            auto j = entryToJson(*s, entries[i], withValues);
            j["index"] = i;
            arr.push_back(j);
        }
        if (ctx.out.json) ctx.out.setJson(arr);
        else {
            for (const auto &e : arr) {
                std::string line = std::to_string(e["index"].get<long long>()) + ": " +
                                   e["address"].get<std::string>() + " " + e["type"].get<std::string>();
                if (e.contains("value")) line += " = " + e["value"].get<std::string>();
                if (e["frozen"].get<bool>()) line += " [frozen]";
                if (!e["description"].get<std::string>().empty()) line += " ; " + e["description"].get<std::string>();
                ctx.out.line(line);
            }
            if (arr.empty()) ctx.out.line("(empty watch list)");
        }
        return kExitOk;
    }
    return usageError(ctx, *findSpec("watch"));
}

int cmdTable(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("table"));
    const std::string &sub = pos[0];
    const std::string &file = pos[1];
    auto *table = s->cheatTable.get();

    if (sub == "save") {
        core_ns::TableSaveOptions opts;
        opts.includeOffsets = t.has("--offsets");
        if (!table->saveToFile(file, opts)) {
            return fail(ctx, kExitFileIo, "file_io", "failed to write " + file);
        }
        if (ctx.out.json) ctx.out.setJson({{"saved", file}});
        return kExitOk;
    }
    if (sub == "load") {
        core_ns::TableLoadOptions opts;
        opts.activateScripts = t.has("--activate-scripts");
        opts.loadPointerOffsets = t.has("--offsets");
        if (!table->loadFromFile(file, opts)) {
            return fail(ctx, kExitFileIo, "file_io", "failed to load " + file + " (missing or no entries)");
        }
        s->updateFreezePump();
        if (ctx.out.json) ctx.out.setJson({{"loaded", file}, {"entries", table->size()}});
        else ctx.out.line("loaded " + std::to_string(table->size()) + " entries");
        return kExitOk;
    }
    return usageError(ctx, *findSpec("table"));
}

int cmdSnapshot(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("snapshot"));
    if (pos[0] == "take") {
        if (!s->scanner || s->scanner->results().empty()) {
            return fail(ctx, kExitGeneric, "no_scan", "run a scan before taking a snapshot");
        }
        s->snapshotValues.clear();
        for (const auto &r : s->scanner->results()) s->snapshotValues[r.address] = r.raw;
        s->hasSnapshot = true;
        return kExitOk;
    }
    if (pos[0] == "diff") {
        if (!s->hasSnapshot) return fail(ctx, kExitGeneric, "no_snapshot", "take a snapshot first");
        if (!s->scanner) return fail(ctx, kExitGeneric, "no_scan", "no scan results to compare");
        long long limit = t.intValue("--limit").value_or(100);
        auto changed = core_ns::diffSnapshot(s->snapshotValues, s->scanner->results());
        nlohmann::json arr = nlohmann::json::array();
        for (size_t i = 0; i < changed.size() && static_cast<long long>(i) < limit; ++i) {
            uintptr_t addr = changed[i];
            arr.push_back({{"address", addrHex(addr)},
                           {"old", s->snapshotValues.at(addr)},
                           {"new", s->liveValues.count(addr) ? s->liveValues[addr] : 0}});
        }
        if (ctx.out.json) {
            ctx.out.setJson({{"differences", changed.size()}, {"rows", arr}});
        } else {
            for (const auto &r : arr) {
                ctx.out.line(r["address"].get<std::string>());
            }
            ctx.out.line(std::to_string(changed.size()) + " addresses differ");
        }
        return kExitOk;
    }
    return usageError(ctx, *findSpec("snapshot"));
}

int cmdMeta(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    if (!s->scanner || s->scanner->results().empty()) {
        return fail(ctx, kExitGeneric, "no_scan", "run a scan first");
    }
    long long limit = t.intValue("--limit").value_or(20);
    auto meta = core_ns::analyzeMetaResults(*s->target, s->scanner->results(), s->resultType);
    std::vector<const std::pair<const uintptr_t, core_ns::MetaEntry> *> ranked;
    ranked.reserve(meta.size());
    for (const auto &kv : meta) ranked.push_back(&kv);
    std::sort(ranked.begin(), ranked.end(), [](auto *a, auto *b) { return a->second.score > b->second.score; });
    nlohmann::json arr = nlohmann::json::array();
    for (size_t i = 0; i < ranked.size() && static_cast<long long>(i) < limit; ++i) {
        arr.push_back({{"address", addrHex(ranked[i]->first)},
                       {"score", ranked[i]->second.score},
                       {"guessedType", core_ns::typeToString(ranked[i]->second.guessedType)},
                       {"pointerCandidate", ranked[i]->second.pointerCandidate},
                       {"group", ranked[i]->second.groupLabel}});
    }
    if (ctx.out.json) {
        ctx.out.setJson({{"analyzed", meta.size()}, {"top", arr}});
    } else {
        for (const auto &m : arr) {
            ctx.out.line(m["address"].get<std::string>() + " score=" + m["score"].dump() + " type=" +
                         m["guessedType"].get<std::string>() +
                         (m["pointerCandidate"].get<bool>() ? " [ptr]" : ""));
        }
    }
    return kExitOk;
}

int cmdMonitor(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.size() < 2) return usageError(ctx, *findSpec("monitor"));
    std::string err;
    auto addrOpt = resolveAddrExpr(*s->target, pos[0], err);
    if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
    core_ns::ValueType vt = core_ns::ValueType::Int32;
    size_t len = 8;
    {
        if (!parseTypeSpec(pos[1], vt, len, err)) {
            return fail(ctx, kExitUsage, "invalid_type", err);
        }
    }
    long long intervalMs = t.intValue("--interval").value_or(100);
    if (intervalMs < 10) intervalMs = 10;

    size_t readLen = core_ns::sizeForType(vt);
    if (readLen == 0) readLen = len;
    std::vector<uint8_t> last;
    {
        std::vector<uint8_t> buf(readLen);
        if (s->target->readMemory(*addrOpt, buf.data(), buf.size())) last = buf;
    }
    if (ctx.connFd >= 0) {
        nlohmann::json start = {{"event", "monitor.start"}, {"address", addrHex(*addrOpt)}};
        writeLineFd(ctx.connFd, start.dump());
    }
    while (!ctx.stopFlag->load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(intervalMs)));
        std::vector<uint8_t> cur(readLen);
        if (!s->target->readMemory(*addrOpt, cur.data(), cur.size())) continue;
        if (cur == last) continue;
        nlohmann::json ev = {{"event", "monitor.change"},
                             {"address", addrHex(*addrOpt)},
                             {"old", core_ns::formatValueBytes(last.data(), last.size(), vt)},
                             {"new", core_ns::formatValueBytes(cur.data(), cur.size(), vt)}};
        last = cur;
        if (ctx.connFd >= 0 && !writeLineFd(ctx.connFd, ev.dump())) break;
    }
    if (ctx.connFd >= 0) writeLineFd(ctx.connFd, "{\"event\":\"monitor.end\"}");
    return kExitOk;
}

int cmdWp(CmdCtx &ctx, Tokens &t) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    if (pos.empty()) return usageError(ctx, *findSpec("wp"));
    const std::string &sub = pos[0];

    if (sub == "start") {
        if (pos.size() < 3) return usageError(ctx, *findSpec("wp"));
        std::string err;
        auto addrOpt = resolveAddrExpr(*s->target, pos[1], err);
        if (!addrOpt) return fail(ctx, kExitInvalidValue, "invalid_address", err);
        core_ns::WatchType wt = pos[2] == "access" ? core_ns::WatchType::Accesses : core_ns::WatchType::Writes;
        size_t len = 4;
        if (pos.size() >= 4) {
            len = static_cast<size_t>(strtoull(pos[3].c_str(), nullptr, 0));
        }
        std::string name = t.value("--name").value_or("wp" + std::to_string(s->wpSessions.size()));
        for (const auto &existing : s->wpSessions) {
            if (existing.name == name) {
                return fail(ctx, kExitUsage, "duplicate_name", "watchpoint '" + name + "' already exists");
            }
        }
        auto session = std::make_unique<core_ns::DebugWatchSession>(*s->target, *addrOpt, wt, len);
        session->start();
        WatchSessionRec rec;
        rec.name = name;
        rec.session = std::move(session);
        s->wpSessions.push_back(std::move(rec));
        if (ctx.out.json) {
            ctx.out.setJson({{"name", name}, {"address", addrHex(*addrOpt)}, {"running", true}});
        }
        return kExitOk;
    }
    if (sub == "stop") {
        std::string name = t.value("--name").value_or("");
        for (auto it = s->wpSessions.begin(); it != s->wpSessions.end(); ++it) {
            if (!name.empty() && it->name != name) continue;
            it->session->stop();
            s->wpSessions.erase(it);
            if (ctx.out.json) ctx.out.setJson({{"stopped", name.empty() ? "all" : name}});
            return kExitOk;
        }
        return fail(ctx, kExitNoTarget, "not_found", "no watchpoint named '" + name + "'");
    }
    if (sub == "hits" || sub == "list") {
        std::string nameFilter = t.value("--name").value_or("");
        nlohmann::json arr = nlohmann::json::array();
        for (const auto &rec : s->wpSessions) {
            if (sub == "hits" && !nameFilter.empty() && rec.name != nameFilter) continue;
            if (sub == "list") {
                arr.push_back({{"name", rec.name},
                               {"address", addrHex(rec.session->address())},
                               {"running", rec.session->isRunning()},
                               {"length", rec.session->length()}});
                continue;
            }
            nlohmann::json hitsArr = nlohmann::json::array();
            for (const auto &kv : rec.session->snapshot()) {
                hitsArr.push_back({{"rip", addrHex(kv.first)},
                                   {"count", kv.second.count},
                                   {"bytes", kv.second.bytes},
                                   {"opcode", kv.second.opcode}});
            }
            arr.push_back({{"name", rec.name},
                           {"address", addrHex(rec.session->address())},
                           {"uniqueRips", hitsArr.size()},
                           {"hits", hitsArr}});
        }
        if (ctx.out.json) ctx.out.setJson(arr);
        else {
            for (const auto &w : arr) {
                ctx.out.line(w.dump());
            }
            if (arr.empty()) ctx.out.line("(no watchpoints)");
        }
        return kExitOk;
    }
    return usageError(ctx, *findSpec("wp"));
}

int cmdAaManage(CmdCtx &ctx, Tokens &t, const std::string &op) {
    TargetSession *s = nullptr;
    int rc = requireSession(ctx, &s);
    if (rc != kExitOk) return rc;
    auto pos = t.positionals();
    const CmdSpec *usageSpec =
        op == "store" ? findSpec("aa-store") : (op == "disable" ? findSpec("aa-disable") : findSpec("aa-enable"));
    if (pos.empty()) return usageError(ctx, *usageSpec);

    std::string name = pos[0];
    std::string text;

    if (op == "store") {
        if (pos.size() < 2) return usageError(ctx, *usageSpec);
        std::ifstream f(pos[1]);
        if (!f.good()) return fail(ctx, kExitFileIo, "file_io", "cannot open " + pos[1]);
        std::stringstream ss;
        ss << f.rdbuf();
        text = ss.str();
        s->scripts[name] = text;
        s->scriptState[name] = false;
        if (ctx.out.json) ctx.out.setJson({{"script", name}, {"stored", true}});
        else ctx.out.line("stored script '" + name + "'");
        return kExitOk;
    }

    auto it = s->scripts.find(name);
    if (it == s->scripts.end()) return fail(ctx, kExitNoTarget, "not_found", "no script named '" + name + "'");
    text = it->second;

    core_ns::AutoAssembler runner(*s->injector);

    if (op == "enable") {
        if (!s->scriptState[name]) {
            std::string log;
            if (!runner.enableScript(text, &log)) {
                return fail(ctx, kExitGeneric, "script_failed", log.empty() ? "enable failed" : log);
            }
            s->scriptState[name] = true;
        }
        if (ctx.out.json) ctx.out.setJson({{"script", name}, {"enabled", true}});
        else ctx.out.line("enabled '" + name + "'");
        return kExitOk;
    }
    if (op == "disable") {
        if (s->scriptState[name]) {
            std::vector<std::string> errors;
            auto parsed = runner.parse(text, errors);
            if (!parsed) return fail(ctx, kExitGeneric, "parse_error", "stored script failed to parse");
            applyDisableSection(*s, *parsed);
            s->scriptState[name] = false;
        }
        if (ctx.out.json) ctx.out.setJson({{"script", name}, {"disabled", true}});
        else ctx.out.line("disabled '" + name + "'");
        return kExitOk;
    }
    return usageError(ctx, *usageSpec);
}

} // namespace

void registerSessionCommands(std::vector<CmdSpec> &cmds) {
    cmds.push_back({"attach", "<pid|name> [--session NAME]", "attach and create a daemon session", true, cmdAttach});
    cmds.push_back({"detach", "[--session NAME]", "detach a session", true, cmdDetach});
    cmds.push_back({"status", "", "list daemon sessions", true, cmdStatus});
    cmds.push_back({"scan", "first|next|undo|reset|count|list|cancel [...]", "scan workflow (daemon)", true, cmdScan});
    cmds.push_back({"watch", "add|rm|set|freeze|script|list ...", "cheat-table watch list (daemon)", true, cmdWatch});
    cmds.push_back({"table", "save|load <file>", "save/load cheat table json (daemon)", true, cmdTable});
    cmds.push_back({"snapshot", "take|diff [--limit N]", "snapshot scan values and diff later", true, cmdSnapshot});
    cmds.push_back({"meta", "[--limit N]", "heuristic ranking of current scan results", true, cmdMeta});
    cmds.push_back({"monitor", "<addr> <type[@len]> [--interval ms]", "stream value changes as NDJSON events", true, cmdMonitor});
    cmds.push_back({"wp", "start|stop|hits|list [...]", "hardware watchpoints via ce_watch", true, cmdWp});
    cmds.push_back({"aa-store", "<name> <file>", "store an AA script for later enable/disable", true,
                    [](CmdCtx &c, Tokens &t) { return cmdAaManage(c, t, "store"); }});
    cmds.push_back({"aa-enable", "<name>", "enable stored AA script by name", true,
                    [](CmdCtx &c, Tokens &t) { return cmdAaManage(c, t, "enable"); }});
    cmds.push_back({"aa-disable", "<name>", "disable stored AA script by name", true,
                    [](CmdCtx &c, Tokens &t) { return cmdAaManage(c, t, "disable"); }});
}

} // namespace cli
