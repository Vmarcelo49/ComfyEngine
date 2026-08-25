#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/MemoryScanner.h"

namespace core {
class TargetProcess;
class CodeInjector;
}

namespace cli {

constexpr int kExitOk = 0;
constexpr int kExitGeneric = 1;
constexpr int kExitUsage = 2;
constexpr int kExitNotAttached = 3;
constexpr int kExitPtraceDenied = 4;
constexpr int kExitTargetGone = 5;
constexpr int kExitInvalidValue = 6;
constexpr int kExitFileIo = 7;
constexpr int kExitCancelled = 8;
constexpr int kExitNoTarget = 9;

class Tokens {
public:
    Tokens() = default;
    explicit Tokens(std::vector<std::string> tokens) : tokens_(std::move(tokens)) {}

    const std::vector<std::string> &all() const { return tokens_; }
    size_t size() const { return tokens_.size(); }
    bool empty() const { return tokens_.empty(); }
    const std::string &operator[](size_t i) const { return tokens_[i]; }

    std::vector<std::string> positionals() const;
    bool has(const std::string &flag) const;
    std::optional<std::string> value(const std::string &flag) const;
    std::optional<long long> intValue(const std::string &flag) const;
    std::optional<double> doubleValue(const std::string &flag) const;

private:
    std::vector<std::string> tokens_;
};

struct CmdOut {
    bool json{false};
    nlohmann::json jdoc = nlohmann::json::object();
    std::vector<std::string> lines;

    void line(std::string s) { lines.push_back(std::move(s)); }
    void setJson(nlohmann::json j) {
        json = true;
        jdoc = std::move(j);
    }
};

struct CliError {
    int exitCode{kExitOk};
    std::string code;
    std::string message;
    std::string hint;
};

class SessionManager;

struct CmdCtx {
    core::TargetProcess *proc{nullptr};
    core::CodeInjector *injector{nullptr};
    SessionManager *mgr{nullptr};
    std::string sessionName{"default"};
    CmdOut out;
    CliError err;
    int connFd{-1};
    std::atomic<bool>* stopFlag{nullptr};
};

struct CmdSpec {
    const char *name;
    const char *usage;
    const char *help;
    bool daemonOnly;
    std::function<int(CmdCtx &, Tokens &)> run;
};

const std::vector<CmdSpec> &registry();
void registerStatelessCommands(std::vector<CmdSpec> &cmds);
void registerSessionCommands(std::vector<CmdSpec> &cmds);

int fail(CmdCtx &ctx, int exitCode, std::string code, std::string message, std::string hint = "");
int usageError(CmdCtx &ctx, const CmdSpec &spec);
const CmdSpec *findSpec(const std::string &name);
std::string cacheDir();
bool parseTypeSpec(const std::string &spec, core::ValueType &type, size_t &len, std::string &err,
                   bool *ptrOut = nullptr);
std::string trimNuls(const std::string &s);

std::optional<uintptr_t> resolveAddrExpr(core::TargetProcess &proc, const std::string &expr, std::string &errOut);
std::vector<uint8_t> parseHexBytesStr(const std::string &s);

std::string addrHex(uintptr_t a);

} // namespace cli
