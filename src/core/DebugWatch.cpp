#include "core/DebugWatch.h"
#include "core/TargetProcess.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <csignal>
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace core {

static inline void logWatch(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::fprintf(stderr, "[watch] ");
    std::vfprintf(stderr, fmt, ap);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
    va_end(ap);
}

namespace {
std::mutex gWatcherMapMutex;
std::unordered_map<pid_t, std::vector<DebugWatchSession *>> gWatcherMap;

void registerWatcherSession(pid_t pid, DebugWatchSession *session) {
    std::lock_guard<std::mutex> lock(gWatcherMapMutex);
    gWatcherMap[pid].push_back(session);
}

void unregisterWatcherSession(pid_t pid, DebugWatchSession *session) {
    std::lock_guard<std::mutex> lock(gWatcherMapMutex);
    auto it = gWatcherMap.find(pid);
    if (it == gWatcherMap.end()) return;
    auto &vec = it->second;
    vec.erase(std::remove(vec.begin(), vec.end(), session), vec.end());
    if (vec.empty()) {
        gWatcherMap.erase(it);
    }
}
}

DebugWatchSession::DebugWatchSession(TargetProcess &proc, uintptr_t addr,
                                     WatchType type, size_t lenBytes)
    : proc_(proc), address_(addr), type_(type), len_(lenBytes) {
    if (len_ != 1 && len_ != 2 && len_ != 4 && len_ != 8) {
        len_ = 4;
    }
}

DebugWatchSession::~DebugWatchSession() {
    stop();
}

void DebugWatchSession::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&DebugWatchSession::loop, this);
}

void DebugWatchSession::stop() {
    bool wasRunning = running_.exchange(false);
    pid_t targetPid = proc_.pid();
    if (wasRunning) {
        logWatch("stop(): requesting shutdown childPid=%d", childPid_);

        if (childPid_ > 0) {
            kill(childPid_, SIGINT);
        }
        if (childFd_ != -1) {
            logWatch("stop(): closing pipe fd=%d", childFd_);
            close(childFd_);
            childFd_ = -1;
        }
        if (childCmdFd_ != -1) {
            close(childCmdFd_);
            childCmdFd_ = -1;
        }
        if (childRespFd_ != -1) {
            close(childRespFd_);
            childRespFd_ = -1;
        }

        bool childKilled = false;
        if (childPid_ > 0) {
            logWatch("stop(): waiting for child %d", childPid_);
            const int maxTries = 50;
            for (int i = 0; i < maxTries; ++i) {
                pid_t w = waitpid(childPid_, nullptr, WNOHANG);
                if (w == childPid_) {
                    logWatch("stop(): child %d exited", childPid_);
                    childPid_ = -1;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (i == maxTries / 2) {
                    logWatch("stop(): child still running, sending SIGKILL");
                    kill(childPid_, SIGKILL);
                    childKilled = true;
                }
            }
            if (childPid_ > 0) {
                logWatch("stop(): child did not exit gracefully (pid=%d)", childPid_);
                childPid_ = -1;
            }
        }

        if (childKilled) {
            logWatch("stop(): performing fallback DR cleanup");
            clearHardwareWatchpointsFallback();
        }
    }

    if (thread_.joinable()) {
        logWatch("stop(): joining watcher thread");
        thread_.join();
    }
    unregisterWatcherSession(targetPid, this);
    logWatch("stop(): done");
}

std::vector<std::pair<uint64_t, WatchHit>> DebugWatchSession::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<uint64_t, WatchHit>> out;
    out.reserve(hits_.size());
    for (const auto &kv : hits_) {
        out.push_back(kv);
    }
    return out;
}

static std::string resolveCeWatchPath() {
    // Try to locate ce_watch in a sibling ce_watch/ directory of any
    // ancestor of the executable's directory, e.g.:
    //   <build>/src/cli/comfyd  ->  <build>/ce_watch/ce_watch
    char exeBuf[PATH_MAX];
    ssize_t n = ::readlink("/proc/self/exe", exeBuf, sizeof(exeBuf) - 1);
    if (n > 0) {
        exeBuf[n] = '\0';
        std::string exePath(exeBuf);
        std::string dir = exePath;
        for (int depth = 0; depth < 6; ++depth) {
            auto slash = dir.find_last_of('/');
            if (slash == std::string::npos) break;
            dir = dir.substr(0, slash);
            std::string candidate = dir + "/ce_watch/ce_watch";
            if (::access(candidate.c_str(), X_OK) == 0) {
                return candidate;
            }
        }
    }
    // Fallback to PATH lookup.
    return "ce_watch";
}

void DebugWatchSession::loop() {
    pid_t pid = proc_.pid();
    if (pid <= 0) {
        running_.store(false);
        return;
    }

    std::string ceWatchPath = resolveCeWatchPath();
    logWatch("loop(): launching %s pid=%d addr=0x%llx len=%zu mode=%s",
             ceWatchPath.c_str(),
             static_cast<int>(pid),
             static_cast<unsigned long long>(address_),
             len_,
             (type_ == WatchType::Writes ? "write" : "access"));

    int pipefd[2];
    int cmdPipe[2];
    int respPipe[2];
    if (pipe(pipefd) == -1) {
        logWatch("pipe failed: %s", std::strerror(errno));
        running_.store(false);
        return;
    }
    if (pipe(cmdPipe) == -1) {
        logWatch("pipe failed: %s", std::strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        running_.store(false);
        return;
    }
    if (pipe(respPipe) == -1) {
        logWatch("pipe failed: %s", std::strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        close(cmdPipe[0]);
        close(cmdPipe[1]);
        running_.store(false);
        return;
    }

    childPid_ = fork();
    if (childPid_ == -1) {
        logWatch("fork failed: %s", std::strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        running_.store(false);
        return;
    }

    if (childPid_ == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        close(cmdPipe[1]);
        close(respPipe[0]);

        char cmdBuf[16];
        char respBuf[16];
        std::snprintf(cmdBuf, sizeof(cmdBuf), "%d", cmdPipe[0]);
        std::snprintf(respBuf, sizeof(respBuf), "%d", respPipe[1]);
        ::setenv("COMFYENGINE_WATCH_CMD_FD", cmdBuf, 1);
        ::setenv("COMFYENGINE_WATCH_RESP_FD", respBuf, 1);

        char pidBuf[32];
        char addrBuf[32];
        char lenBuf[16];
        std::snprintf(pidBuf, sizeof(pidBuf), "%d", static_cast<int>(pid));
        std::snprintf(addrBuf, sizeof(addrBuf), "0x%llx",
                      static_cast<unsigned long long>(address_));
        std::snprintf(lenBuf, sizeof(lenBuf), "%zu", len_);
        const char *modeStr = (type_ == WatchType::Writes) ? "write" : "access";

        char *argv[] = {
            const_cast<char *>(ceWatchPath.c_str()),
            pidBuf,
            addrBuf,
            const_cast<char *>(modeStr),
            lenBuf,
            nullptr
        };

        ::execv(ceWatchPath.c_str(), argv);
        _exit(127);
    }

    close(pipefd[1]);
    close(cmdPipe[0]);
    close(respPipe[1]);
    childFd_ = pipefd[0];
    childCmdFd_ = cmdPipe[1];
    childRespFd_ = respPipe[0];

    registerWatcherSession(pid, this);

    FILE *fp = ::fdopen(childFd_, "r");
    if (!fp) {
        logWatch("fdopen failed: %s", std::strerror(errno));
        close(childFd_);
        childFd_ = -1;
        running_.store(false);
        return;
    }

    char lineBuf[1024];
    while (running_.load()) {
        if (!std::fgets(lineBuf, sizeof(lineBuf), fp)) {
            logWatch("loop(): pipe EOF");
            break; // EOF or error; watcher is gone.
        }
        logWatch("loop(): %s", lineBuf);
        parseLine(std::string(lineBuf));
    }

    std::fclose(fp);
    childFd_ = -1;
    unregisterWatcherSession(pid, this);
    running_.store(false);
}

void DebugWatchSession::parseLine(const std::string &line) {
    // Expected ce_watch format (approx):
    // tid=<t> rip=0x<hex> [dr6=...] bytes=<hex bytes> inst=<mnemonic...>
    auto ripPos = line.find("rip=0x");
    if (ripPos == std::string::npos) return;
    ripPos += 6;

    unsigned long long ripVal = 0;
    size_t i = ripPos;
    while (i < line.size()) {
        char c = line[i];
        int v = 0;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') v = 10 + (c - 'A');
        else break;
        ripVal = (ripVal << 4) | static_cast<unsigned long long>(v);
        ++i;
    }

    auto bytesPos = line.find("bytes=", i);
    if (bytesPos == std::string::npos) return;
    bytesPos += 6;

    auto instPos = line.find("inst=", bytesPos);
    if (instPos == std::string::npos) return;

    auto trim = [](std::string s) {
        const char *ws = " \t\r\n";
        auto first = s.find_first_not_of(ws);
        if (first == std::string::npos) return std::string();
        auto last = s.find_last_not_of(ws);
        return s.substr(first, last - first + 1);
    };

    std::string bytesStr = trim(line.substr(bytesPos, instPos - bytesPos));
    std::string instStr = trim(line.substr(instPos + 5));

    std::lock_guard<std::mutex> lock(mutex_);
    auto &hit = hits_[static_cast<uint64_t>(ripVal)];
    hit.count += 1;
    if (hit.bytes.empty()) {
        hit.bytes = bytesStr;
        hit.opcode = instStr;
        hit.type = type_;
        hit.access = (type_ == WatchType::Writes ? "write" : "access");
    }
}

void DebugWatchSession::clearHardwareWatchpointsFallback() {
    auto tids = proc_.listThreads();
    if (tids.empty()) return;

    for (pid_t tid : tids) {
        if (tid <= 0) continue;
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
            logWatch("fallback: attach tid=%d failed: %s", tid, std::strerror(errno));
            continue;
        }

        int status = 0;
        if (waitpid(tid, &status, __WALL) == -1) {
            logWatch("fallback: waitpid tid=%d failed: %s", tid, std::strerror(errno));
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            continue;
        }

        ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg[7]), 0);
        ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg[0]), 0);
        ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg[6]), 0);

        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        logWatch("fallback: cleared tid=%d", tid);
    }
}

bool DebugWatchSession::sendWriteCommand(uintptr_t address, const uint8_t *data, size_t len) {
    if (childCmdFd_ == -1 || childRespFd_ == -1 || len == 0) return false;
    std::lock_guard<std::mutex> lock(commandMutex_);
    std::ostringstream oss;
    oss << "WRITE " << std::hex << std::nouppercase << address;
    for (size_t i = 0; i < len; ++i) {
        oss << ' ' << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned int>(data[i]);
    }
    oss << "\n";
    std::string cmd = oss.str();
    ssize_t total = static_cast<ssize_t>(cmd.size());
    ssize_t written = ::write(childCmdFd_, cmd.data(), cmd.size());
    if (written != total) return false;

    std::string response;
    char ch = 0;
    while (true) {
        ssize_t n = ::read(childRespFd_, &ch, 1);
        if (n <= 0) return false;
        if (ch == '\n') break;
        response.push_back(ch);
    }
    return response == "OK";
}

bool DebugWatchSession::writeViaWatcher(pid_t pid, uintptr_t address, const uint8_t *data, size_t len) {
    std::vector<DebugWatchSession *> sessions;
    {
        std::lock_guard<std::mutex> lock(gWatcherMapMutex);
        auto it = gWatcherMap.find(pid);
        if (it != gWatcherMap.end()) {
            sessions = it->second;
        }
    }
    if (sessions.empty()) return false;
    for (auto *session : sessions) {
        if (session && session->sendWriteCommand(address, data, len)) {
            return true;
        }
    }
    return false;
}

} // namespace core
