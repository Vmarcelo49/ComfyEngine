#pragma once

#include "core/CodeInjector.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

class AutoAssembler {
public:
    struct Command {
        enum class Type { Patch, Restore };
        Type type{Type::Patch};
        uintptr_t address{0};
        std::vector<uint8_t> bytes;
    };
    using CommandList = std::vector<Command>;
    struct Script {
        CommandList enableCmds;
        CommandList disableCmds;
    };

    explicit AutoAssembler(CodeInjector &injector);

    static std::optional<Command> parseLine(const std::string &line, const std::unordered_map<std::string, uintptr_t> &symbols,
                                            std::string &errorOut);
    std::optional<Script> parse(const std::string &scriptText, std::vector<std::string> &errors,
                                std::vector<std::string> *logOut = nullptr);

    bool apply(const CommandList &cmds);
    bool restore(const CommandList &cmds);

    bool enableScript(const std::string &scriptText, std::string *logOut = nullptr);
    bool disableScript(std::string *logOut = nullptr);
    bool isEnabled() const { return enabled_; }

    std::optional<uintptr_t> scanAob(const std::string &pattern, std::string &errorOut,
                                     const std::string &moduleFilter = std::string()) const;
    bool resolveOperand(const std::string &addrStr, uintptr_t &outAddr, std::string &errorOut) const;
    std::unordered_map<std::string, uintptr_t> collectModuleBases() const;

    static std::string ensureEnableSection(const std::string &scriptText);
    static std::string joinBytesHex(const std::vector<uint8_t> &bytes);
    static std::string codeInjectionTemplate(uintptr_t address, const std::vector<uint8_t> &originalBytes);
    static std::string aobInjectionTemplate(const std::vector<uint8_t> &patternBytes);
    static std::string emptyTemplate();
    static std::string patchScript(uintptr_t address, const std::vector<uint8_t> &patchBytes, bool viaAob,
                                   const std::vector<uint8_t> *originalBytes = nullptr);

private:
    CodeInjector &injector_;
    std::unordered_map<std::string, uintptr_t> symbols_;
    Script last_{};
    bool enabled_{false};
};

} // namespace core
