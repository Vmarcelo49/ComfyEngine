#include "../common/Cli.h"
#include "../common/Ipc.h"

#include "core/ScalarCodec.h"
#include "Sessions.h"

#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <thread>

namespace cli {

namespace {

std::atomic<bool> gShutdown{false};

void onSignal(int) {
    gShutdown.store(true);
}

bool parseRequestLine(const std::string &line, nlohmann::json &req, std::string &errOut) {
    req = nlohmann::json::parse(line, nullptr, false);
    if (req.is_discarded() || !req.is_object()) {
        errOut = "request must be a JSON object";
        return false;
    }
    if (!req.contains("cmd") || !req["cmd"].is_string()) {
        errOut = "request missing string field 'cmd'";
        return false;
    }
    return true;
}

void sendResponse(int fd, long long id, CmdCtx &ctx) {
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
    writeLine(fd, resp.dump());
}

int runCommand(CmdCtx &ctx, const std::string &cmdName, Tokens &tokens) {
    const CmdSpec *spec = findSpec(cmdName);
    if (!spec) return kExitUsage;
    return spec->run(ctx, tokens);
}

// Executes one request: builds context from session or ephemeral --pid target.
void handleRequest(int fd, const nlohmann::json &req) {
    long long id = req.value("id", 0);
    std::string cmd = req["cmd"].get<std::string>();
    Tokens tokens(req.value("tokens", std::vector<std::string>{}));

    const CmdSpec *spec = findSpec(cmd);
    if (!spec) {
        CmdCtx errCtx;
        fail(errCtx, kExitUsage, "unknown_command", "unknown command: " + cmd);
        sendResponse(fd, id, errCtx);
        return;
    }

    auto pidToken = tokens.value("--pid");
    std::string sessionName = tokens.value("--session").value_or("default");

    bool managesSessions = (cmd == "attach" || cmd == "detach" || cmd == "status");

    CmdCtx ctx;
    ctx.sessionName = sessionName;
    ctx.connFd = fd;
    ctx.out.json = req.value("json", false);

    if (!managesSessions && pidToken && !spec->daemonOnly) {
        pid_t pid = static_cast<pid_t>(std::stoll(*pidToken));
        auto proc = std::make_unique<core::TargetProcess>();
        if (!proc->attach(pid)) {
            fail(ctx, kExitPtraceDenied, "attach_failed", "cannot access pid " + std::to_string(pid),
                 core::ptraceHint());
            sendResponse(fd, id, ctx);
            return;
        }
        core::CodeInjector injector(*proc);
        ctx.proc = proc.get();
        ctx.injector = &injector;
        runCommand(ctx, cmd, tokens);
        sendResponse(fd, id, ctx);
        return;
    }

    TargetSession *session = nullptr;
    if (!managesSessions) {
        session = SessionManager::instance().get(sessionName);
        if (!session || !session->target || !session->target->isAttached()) {
            fail(ctx, kExitNotAttached, "not_attached",
                 "no active session '" + sessionName + "' (run: comfy attach <pid|name>)");
            sendResponse(fd, id, ctx);
            return;
        }
    }

    std::atomic<bool> stop{false};
    ctx.stopFlag = &stop;
    ctx.mgr = &SessionManager::instance();
    if (session) {
        ctx.proc = session->target.get();
        ctx.injector = session->injector.get();
    }

    bool streaming = (cmd == "monitor");
    std::thread reader;
    if (streaming) {
        int connFd = fd;
        reader = std::thread([connFd, &stop]() {
            std::string line;
            while (readLine(connFd, line)) {
                if (line.find("\"stop\"") != std::string::npos || line == "stop") break;
            }
            stop.store(true);
        });
    }

    int rc = spec->run(ctx, tokens);

    if (streaming && reader.joinable()) {
        if (!stop.load()) {
            writeLine(fd, "{\"cmd\":\"stop\"}");
        }
        reader.join();
    }

    ctx.err.exitCode = rc == kExitOk ? kExitOk : (ctx.err.exitCode == kExitOk ? kExitGeneric : ctx.err.exitCode);
    sendResponse(fd, id, ctx);
}

void handleConnection(int fd) {
    std::string line;
    while (readLine(fd, line)) {
        if (line.empty()) continue;
        nlohmann::json req;
        std::string err;
        if (!parseRequestLine(line, req, err)) {
            CmdCtx errCtx;
            fail(errCtx, kExitUsage, "bad_request", err);
            sendResponse(fd, 0, errCtx);
            continue;
        }
        handleRequest(fd, req);
    }
    close(fd);
}

} // namespace

int daemonMain(int argc, char **argv) {
    std::string socketPath = defaultSocketPath();
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--socket-path" || a == "--socket") && i + 1 < argc) {
            socketPath = argv[++i];
        } else if (a == "--help" || a == "-h") {
            printf("usage: comfyd [--socket-path PATH]\n\nComfyEngine daemon: owns sessions "
                   "(scans, watchlists, freeze pumps, watchpoints). Start manually; drive it with comfy.\n");
            return 0;
        }
    }

    struct sigaction sa {};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        fprintf(stderr, "comfyd: socket(): %s\n", strerror(errno));
        return 1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    unlink(socketPath.c_str());
    if (bind(server, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        fprintf(stderr, "comfyd: bind(%s): %s\n", socketPath.c_str(), strerror(errno));
        return 1;
    }
    chmod(socketPath.c_str(), 0600);
    if (listen(server, 16) != 0) {
        fprintf(stderr, "comfyd: listen(): %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "comfyd: listening on %s (pid %d)\n", socketPath.c_str(), getpid());

    while (!gShutdown.load()) {
        int conn = accept(server, nullptr, nullptr);
        if (conn < 0) {
            if (errno == EINTR) continue;
            break;
        }
        std::thread(handleConnection, conn).detach();
    }

    SessionManager::instance().destroyAll();
    close(server);
    unlink(socketPath.c_str());
    return 0;
}

} // namespace cli

int main(int argc, char **argv) {
    return cli::daemonMain(argc, argv);
}
