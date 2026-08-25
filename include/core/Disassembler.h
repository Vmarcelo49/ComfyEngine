#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace core {

struct Instruction {
    uint64_t address{0};
    uint16_t size{0};
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();
    Disassembler(const Disassembler &) = delete;
    Disassembler &operator=(const Disassembler &) = delete;

    bool valid() const { return handle_ != nullptr; }

    std::vector<Instruction> disassemble(const uint8_t *code, size_t size, uint64_t baseAddress,
                                         size_t maxInstructions = 0) const;

private:
    void *handle_{nullptr};
};

} // namespace core
