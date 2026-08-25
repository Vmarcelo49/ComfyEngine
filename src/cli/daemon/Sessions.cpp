#include "Sessions.h"

namespace cli {

TargetSession::~TargetSession() {
    if (cheatTable) cheatTable->stopFreezePump();
    for (auto &wp : wpSessions) {
        if (wp.session) wp.session->stop();
    }
}

void TargetSession::updateFreezePump() {
    if (!cheatTable) return;
    bool anyFrozen = false;
    for (const auto &e : cheatTable->snapshot()) {
        if (e.frozen && !e.isScript) {
            anyFrozen = true;
            break;
        }
    }
    if (anyFrozen && !cheatTable->pumpRunning()) {
        cheatTable->startFreezePump();
    } else if (!anyFrozen && cheatTable->pumpRunning()) {
        cheatTable->stopFreezePump();
    }
}

SessionManager &SessionManager::instance() {
    static SessionManager mgr;
    return mgr;
}

TargetSession *SessionManager::get(const std::string &name) {
    auto it = sessions_.find(name);
    return it == sessions_.end() ? nullptr : it->second.get();
}

TargetSession *SessionManager::create(const std::string &name, pid_t pid, const std::string &procName) {
    auto existing = get(name);
    if (existing) destroy(name);
    auto session = std::make_unique<TargetSession>();
    session->name = name;
    session->pid = pid;
    session->procName = procName;
    session->target = std::make_unique<core::TargetProcess>();
    if (!session->target->attach(pid)) {
        return nullptr;
    }
    session->scanner = std::make_unique<core::MemoryScanner>(*session->target);
    session->injector = std::make_unique<core::CodeInjector>(*session->target);
    session->cheatTable = std::make_unique<core::CheatTable>(*session->target);
    TargetSession *raw = session.get();
    sessions_[name] = std::move(session);
    return raw;
}

bool SessionManager::destroy(const std::string &name) {
    auto it = sessions_.find(name);
    if (it == sessions_.end()) return false;
    it->second.reset();
    sessions_.erase(it);
    return true;
}

std::vector<TargetSession *> SessionManager::all() {
    std::vector<TargetSession *> out;
    for (auto &kv : sessions_) out.push_back(kv.second.get());
    return out;
}

void SessionManager::destroyAll() {
    sessions_.clear();
}

} // namespace cli
