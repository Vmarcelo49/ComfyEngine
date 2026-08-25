#pragma once

#include "core/Analysis.h"
#include "core/AutoAssembler.h"
#include "core/CodeInjector.h"
#include "core/CheatTable.h"
#include "core/DebugWatch.h"
#include "core/MemoryScanner.h"
#include "core/TargetProcess.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace cli {

struct WatchSessionRec {
    std::string name;
    std::unique_ptr<core::DebugWatchSession> session;
};

class TargetSession {
public:
    std::mutex mutex;
    std::string name;
    pid_t pid{-1};
    std::string procName;
    std::unique_ptr<core::TargetProcess> target;
    std::unique_ptr<core::MemoryScanner> scanner;
    std::unique_ptr<core::CodeInjector> injector;
    std::unique_ptr<core::CheatTable> cheatTable;
    std::vector<std::vector<core::ScanResult>> scanHistory;
    std::unordered_map<uintptr_t, uint64_t> snapshotValues;
    bool hasSnapshot{false};
    std::unordered_map<std::string, std::string> scripts;
    std::unordered_map<std::string, bool> scriptState;
    std::unordered_map<uintptr_t, uint64_t> liveValues;
    core::ValueType resultType{core::ValueType::Int32};
    core::ScanParams lastParams;
    std::vector<WatchSessionRec> wpSessions;

    ~TargetSession();

    void updateFreezePump();
};

class SessionManager {
public:
    static SessionManager &instance();

    std::mutex mutex;

    TargetSession *get(const std::string &name);
    TargetSession *create(const std::string &name, pid_t pid, const std::string &procName);
    bool destroy(const std::string &name);
    std::vector<TargetSession *> all();
    void destroyAll();

private:
    SessionManager() = default;
    std::unordered_map<std::string, std::unique_ptr<TargetSession>> sessions_;
};

} // namespace cli
