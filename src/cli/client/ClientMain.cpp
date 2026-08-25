#include "../common/Cli.h"
#include "../common/Ipc.h"

#include "core/CodeInjector.h"
#include "core/ScalarCodec.h"

#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>

#include <sys/socket.h>
#include <unistd.h>

namespace cli {

namespace {

struct GlobalOpts {
    bool json{false};
    std::string socketPath{defaultSocketPath()};
};

std::vector<std::string> tokenizeLine(const std::string &line) {
    std::vector<std::string> out;
    std::string cur;
    char quote = 0;
    for (char c : line) {
        if (quote) {
            if (c == quote) quote = 0;
            else cur.push_back(c);
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

nlohmann::json envelope(long long id, CmdCtx &ctx) {
    nlohmann::json resp;
    resp["id"] = id;
    if (ctx.err.exitCode == kExitOk) {
        nlohmann::json out = {{"exit", kExitOk}};
        if (ctx.out.json) {
            out["json"] = true;
            out["doc"] = ctx.out.jdoc;
        } else {
            out["lines"] = ctx.out.lines;
        }
        resp["ok"] = true;
        resp["result"] = out;
    } else {
        resp["ok"] = false;
        resp["error"] = {{"code", ctx.err.code},
                         {"message", ctx.err.message},
                         {"hint", ctx.err.hint},
                         {"exit", ctx.err.exitCode}};
    }
    return resp;
}

void emit(const GlobalOpts &opts, CmdCtx &ctx) {
    if (ctx.err.exitCode == kExitOk) {
        if (ctx.out.json) {
            std::cout << ctx.out.jdoc.dump() << "\n";
        } else {
            for (const auto &l : ctx.out.lines) std::cout << l << "\n";
        }
        std::cout.flush();
        return;
    }
    if (opts.json) {
        nlohmann::json e = {{"error", {{"code", ctx.err.code},
                                       {"message", ctx.err.message},
                                       {"hint", ctx.err.hint},
                                       {"exit", ctx.err.exitCode}}}};
        std::cout << e.dump() << "\n";
    } else {
        fprintf(stderr, "error[%s]: %s\n", ctx.err.code.c_str(), ctx.err.message.c_str());
        if (!ctx.err.hint.empty()) fprintf(stderr, "%s\n", ctx.err.hint.c_str());
    }
    std::cout.flush();
}

bool executeLocal(const GlobalOpts &opts, const std::string &cmdName, Tokens &tokens,
                  long long pidValue, CmdCtx &ctx) {
    static thread_local core::TargetProcess proc;
    static thread_local std::unique_ptr<core::CodeInjector> injector;
    if (pidValue > 0 && (!proc.isAttached() || proc.pid() != static_cast<pid_t>(pidValue))) {
        injector.reset();
    }
    if (!injector && proc.isAttached()) injector = std::make_unique<core::CodeInjector>(proc);
    ctx.out.json = opts.json;
    if (pidValue <= 0 && !proc.isAttached()) return false;
    if (pidValue > 0 && (!proc.isAttached() || proc.pid() != static_cast<pid_t>(pidValue))) {
        injector.reset();
        proc.detach();
        if (!proc.attach(static_cast<pid_t>(pidValue))) {
            fail(ctx, kExitPtraceDenied, "attach_failed", "cannot access pid " + std::to_string(pidValue),
                 core::ptraceHint());
            return true;
        }
    }
    if (proc.isAttached() && !injector) injector = std::make_unique<core::CodeInjector>(proc);
    const CmdSpec *spec = findSpec(cmdName);
    if (!spec) return false;
    ctx.proc = &proc;
    ctx.injector = injector.get();
    spec->run(ctx, tokens);
    return true;
}

int runDirect(const GlobalOpts &opts, const std::string &cmdName, Tokens &tokens) {
    CmdCtx ctx;
    auto pidInt = tokens.intValue("--pid");
    bool ran = executeLocal(opts, cmdName, tokens, pidInt.value_or(0), ctx);
    if (!ran) {
        fail(ctx, kExitUsage, "missing_pid", "'" + cmdName + "' needs --pid P (or attach a session)");
        emit(opts, ctx);
        return ctx.err.exitCode;
    }
    emit(opts, ctx);
    return ctx.err.exitCode;
}

int runRemote(const GlobalOpts &opts, const std::string &cmdName, Tokens &tokens, bool interactiveMonitor) {
    int fd = -1;
    std::string err;
    if (!connectDaemon(opts.socketPath, fd, err)) {
        CmdCtx ctx;
        ctx.out.json = opts.json;
        fail(ctx, kExitGeneric, "daemon_not_running",
             "cannot connect to daemon at " + opts.socketPath, "start it with: comfyd &");
        emit(opts, ctx);
        return kExitGeneric;
    }

    nlohmann::json req = {{"id", 1}, {"cmd", cmdName}, {"tokens", tokens.all()}, {"json", opts.json}};
    writeLine(fd, req.dump());

    void (*oldHandler)(int) = nullptr;
    if (interactiveMonitor) {
        oldHandler = signal(SIGINT, [](int) {
            signal(SIGINT, SIG_DFL);
            raise(SIGINT);
        });
    }

    std::string line;
    int exitCode = kExitOk;
    while (readLine(fd, line)) {
        auto obj = nlohmann::json::parse(line, nullptr, false);
        if (obj.is_discarded() || !obj.is_object()) continue;
        if (obj.contains("event")) {
            if (opts.json) {
                std::cout << line << "\n";
            } else {
                std::string ev = obj["event"].get<std::string>();
                if (ev == "monitor.change") {
                    std::cout << obj.value("address", std::string()) << ": "
                              << obj.value("old", std::string()) << " -> "
                              << obj.value("new", std::string()) << "\n";
                } else if (ev != "monitor.end") {
                    std::cout << line << "\n";
                }
            }
            std::cout.flush();
            continue;
        }
        if (!obj.contains("id")) continue;

        if (interactiveMonitor && oldHandler) signal(SIGINT, oldHandler);

        if (obj.value("ok", false)) {
            const auto &result = obj["result"];
            exitCode = result.value("exit", kExitOk);
            if (result.contains("json") && result["json"].get<bool>()) {
                std::cout << result["doc"].dump() << "\n";
            } else if (result.contains("lines")) {
                for (const auto &l : result["lines"]) std::cout << l.get<std::string>() << "\n";
            }
        } else {
            const auto &e = obj["error"];
            exitCode = e.value("exit", kExitGeneric);
            if (opts.json) {
                std::cout << nlohmann::json({{"error", {{"code", e.value("code", "")},
                                                        {"message", e.value("message", "")},
                                                        {"hint", e.value("hint", "")},
                                                        {"exit", exitCode}}}})
                                 .dump()
                          << "\n";
            } else {
                fprintf(stderr, "error[%s]: %s\n", e.value("code", "").c_str(),
                        e.value("message", "").c_str());
                std::string hint = e.value("hint", "");
                if (!hint.empty()) fprintf(stderr, "%s\n", hint.c_str());
            }
        }
        break;
    }
    close(fd);
    return exitCode;
}

void printHelp() {
    printf("comfy - ComfyEngine CLI\n\nusage: comfy [--json] [--socket-path PATH] <command> [args...]\n\n");
    printf("session commands (require comfyd):\n");
    for (const auto &c : registry()) {
        if (!c.daemonOnly) continue;
        printf("  %-12s %-40s %s\n", c.name, c.usage, c.help);
    }
    printf("\ndirect commands (--pid P, no daemon needed):\n");
    for (const auto &c : registry()) {
        if (c.daemonOnly) continue;
        printf("  %-12s %-40s %s\n", c.name, c.usage, c.help);
    }
    printf("\nbatch: comfy exec -   (NDJSON requests on stdin)\nself-description: comfy schema\n");
}

void printCommandHelp(const std::string &name) {
    const CmdSpec *spec = findSpec(name);
    if (!spec) {
        printf("unknown command '%s'\n", name.c_str());
        return;
    }
    printf("%s - %s\n\nusage: comfy [flags] %s %s\n", spec->name, spec->help, spec->name, spec->usage);
    printf("mode: %s\n\n", spec->daemonOnly ? "daemon session required"
                                                : "direct with --pid P, or daemon session");
    struct Example { const char *cmd; const char *ex; };
    static const Example examples[] = {
        {"read", "comfy read 0x55c0a1b2e140 i32            # scalar\ncomfy read '[0x55c00000+8]+8]+0' i32 # deref chain\ncomfy read 0x55c0a1b2e140 aob@16    # 16 bytes"},
        {"write", "comfy write 0x55c0a1b2e140 i32 9999 [--dry-run]"},
        {"scan", "comfy scan first --type i32 --mode exact --value 100 [--writable]\ncomfy scan next --mode decreased --value 5\ncomfy scan list --with-values --limit 20\ncomfy scan undo | reset | cancel"},
        {"watch", "comfy watch add <addr> <type> [description]\ncomfy watch list [--with-values]\ncomfy watch freeze <index> on|off\ncomfy watch set <index> <value>\ncomfy watch script <index> on|off   # toggle table scripts"},
        {"table", "comfy table save file.json [--offsets]\ncomfy table load file.json [--activate-scripts]"},
        {"monitor", "comfy monitor 0x55c0a1b2e140 i32 --interval 100   # NDJSON events until killed"},
        {"wp", "comfy wp start <addr> write|access [1|2|4|8] [--name N]\ncomfy wp hits [--name N]\ncomfy wp list | stop [--name N]"},
        {"pscan", "comfy pscan 0x55c0a1b2e140 --max-offset 4096 [--writable-only]"},
        {"disasm", "comfy disasm 0x401000 --bytes 128 --count 20"},
        {"patch", "comfy patch 0x401000 90 90 90   # recorded; undo: comfy unpatch 0x401000"},
        {"aa-run", "comfy aa-run script.txt [--section disable]"},
    };
    for (const auto &e : examples) {
        if (name == e.cmd) printf("\nexamples:\n%s\n", e.ex);
    }
    if (name == "read") {
        printf("\naddress expressions:\n"
               "  0x55c0a1b2e140        literal\n"
               "  12345                 decimal literal\n"
               "  gamelib.so+0x1234     module base + offset\n"
               "  0x55c00000+24         arithmetic\n"
               "  [expr]+off]+off]      pointer chain: start at expr, then each\n"
               "                        segment dereferences the current pointer\n"
               "                        and adds off. Nesting [[..]] is invalid.\n");
    }
}

void printSchema() {
    nlohmann::json commands = nlohmann::json::array();
    for (const auto &c : registry()) {
        commands.push_back({{"name", c.name},
                            {"usage", c.usage},
                            {"help", c.help},
                            {"requiresDaemon", c.daemonOnly}});
    }
    nlohmann::json schema = {
        {"version", "1.0"},
        {"protocol",
         "NDJSON over unix socket; request {id,cmd,tokens}, response {id,ok,result|error}"},
        {"commands", commands},
        {"valueTypes", {"byte", "i16", "i32", "i64", "float", "double", "aob@N", "string@N"}},
        {"scanModes", {"exact", "unknown", "changed", "unchanged", "increased", "decreased",
                       "gt", "lt", "between", "aob"}},
        {"addressExpressions", "hex 0x... | decimal | module+offset | [base]+off]+off] pointer chains"},
        {"exitCodes",
         {{"0", "success"}, {"1", "generic failure"}, {"2", "usage"}, {"3", "not attached"},
          {"4", "ptrace denied"}, {"5", "target gone"}, {"6", "invalid address/value/type"},
          {"7", "file io"}, {"8", "cancelled"}, {"9", "no such target object"}}}};
    printf("%s\n", schema.dump(2).c_str());
}

int execBatch(const GlobalOpts &opts) {
    int lastExit = kExitOk;
    std::string line;
    long long counter = 0;
    while (std::getline(std::cin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        ++counter;

        std::string cmd;
        Tokens tokens;
        if (line[0] == '{') {
            auto obj = nlohmann::json::parse(line, nullptr, false);
            if (obj.is_discarded() || !obj.is_object() || !obj.contains("cmd")) {
                std::cout << nlohmann::json({{"id", counter}, {"ok", false},
                                             {"error", {{"code", "bad_request"},
                                                        {"message", "invalid request json"}}}})
                                 .dump()
                          << "\n";
                lastExit = kExitUsage;
                continue;
            }
            cmd = obj["cmd"].get<std::string>();
            if (obj.contains("args") && obj["args"].is_array()) {
                std::vector<std::string> toks;
                for (const auto &a : obj["args"]) toks.push_back(a.get<std::string>());
                tokens = Tokens(toks);
            }
        } else {
            auto toks = tokenizeLine(line);
            if (toks.empty()) continue;
            cmd = toks[0];
            toks.erase(toks.begin());
            tokens = Tokens(toks);
        }

        const CmdSpec *spec = findSpec(cmd);
        if (!spec) {
            std::cout << nlohmann::json({{"id", counter}, {"ok", false},
                                         {"error", {{"code", "unknown_command"},
                                                    {"message", "unknown command: " + cmd}}}})
                             .dump()
                      << "\n";
            lastExit = kExitUsage;
            continue;
        }

        auto pidInt = tokens.intValue("--pid");
        if (!spec->daemonOnly && pidInt.has_value()) {
            CmdCtx ctx;
            executeLocal(opts, cmd, tokens, *pidInt, ctx);
            std::cout << envelope(counter, ctx).dump() << "\n";
            std::cout.flush();
            if (ctx.err.exitCode != kExitOk) lastExit = ctx.err.exitCode;
            continue;
        }

        int fd = -1;
        std::string err;
        if (!connectDaemon(opts.socketPath, fd, err)) {
            std::cout << nlohmann::json({{"id", counter}, {"ok", false},
                                         {"error", {{"code", "daemon_not_running"},
                                                    {"message", "cannot connect to daemon at " + opts.socketPath},
                                                    {"hint", "start it with: comfyd &"}}}})
                             .dump()
                      << "\n";
            lastExit = kExitGeneric;
            continue;
        }
        nlohmann::json req = {{"id", counter}, {"cmd", cmd}, {"tokens", tokens.all()}, {"json", opts.json}};
        writeLine(fd, req.dump());
        std::string resp;
        while (readLine(fd, resp)) {
            auto obj = nlohmann::json::parse(resp, nullptr, false);
            if (obj.is_discarded() || !obj.is_object()) continue;
            if (obj.contains("event")) {
                std::cout << resp << "\n";
                std::cout.flush();
                continue;
            }
            if (obj.value("id", -1) != counter) continue;
            std::cout << resp << "\n";
            std::cout.flush();
            if (obj.value("ok", false)) {
                int rc = obj["result"].value("exit", kExitOk);
                if (rc != kExitOk) lastExit = rc;
            } else {
                lastExit = obj["error"].value("exit", kExitGeneric);
            }
            break;
        }
        close(fd);
    }
    return lastExit;
}

} // namespace

int clientMain(int argc, char **argv) {
    GlobalOpts opts;
    std::vector<std::string> rest;
    std::string cmd;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") opts.json = true;
        else if ((a == "--socket-path" || a == "--socket") && i + 1 < argc) opts.socketPath = argv[++i];
        else if ((a == "--help" || a == "-h" || a == "help") && cmd.empty()) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                printCommandHelp(argv[i + 1]);
            } else {
                printHelp();
            }
            return kExitOk;
        } else if (a == "schema" && cmd.empty()) {
            printSchema();
            return kExitOk;
        } else if (a == "--version" || a == "version") {
            printf("comfy 1.0 (ComfyEngine CLI)\n");
            return kExitOk;
        } else if (cmd.empty() && !a.empty() && a[0] != '-') {
            cmd = a;
        } else {
            rest.push_back(a);
        }
    }

    if (cmd.empty()) {
        printHelp();
        return kExitUsage;
    }

    if (cmd == "exec") {
        if (!rest.empty() && rest[0] == "-") {
            return execBatch(opts);
        }
        fprintf(stderr, "usage: comfy exec -\n");
        return kExitUsage;
    }

    if (!rest.empty() && (rest[0] == "--help" || rest[0] == "-h" || rest[0] == "help")) {
        printCommandHelp(cmd);
        return kExitOk;
    }

    Tokens tokens(rest);
    const CmdSpec *spec = findSpec(cmd);
    if (!spec) {
        CmdCtx ctx;
        ctx.out.json = opts.json;
        fail(ctx, kExitUsage, "unknown_command", "unknown command '" + cmd + "' (see comfy help)");
        emit(opts, ctx);
        return kExitUsage;
    }

    auto pidTok = tokens.value("--pid");
    if ((!spec->daemonOnly && pidTok.has_value()) || cmd == "ps") {
        return runDirect(opts, cmd, tokens);
    }

    return runRemote(opts, cmd, tokens, cmd == "monitor");
}

} // namespace cli

int main(int argc, char **argv) {
    return cli::clientMain(argc, argv);
}
