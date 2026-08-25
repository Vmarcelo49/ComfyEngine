#include "core/Disassembler.h"

#include <capstone/capstone.h>

namespace core {

Disassembler::Disassembler() {
    csh handle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
        handle_ = reinterpret_cast<void *>(handle);
    }
}

Disassembler::~Disassembler() {
    if (handle_) {
        cs_close(reinterpret_cast<csh *>(&handle_));
    }
}

std::vector<Instruction> Disassembler::disassemble(const uint8_t *code, size_t size, uint64_t baseAddress,
                                                   size_t maxInstructions) const {
    std::vector<Instruction> out;
    if (!handle_ || !code || size == 0) return out;
    csh handle = reinterpret_cast<csh>(handle_);
    cs_insn *insns = nullptr;
    size_t count = cs_disasm(handle, code, size, baseAddress, static_cast<size_t>(maxInstructions), &insns);
    if (count == 0) return out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        Instruction insn;
        insn.address = insns[i].address;
        insn.size = insns[i].size;
        insn.mnemonic = insns[i].mnemonic;
        insn.operands = insns[i].op_str;
        insn.bytes.assign(insns[i].bytes, insns[i].bytes + insns[i].size);
        out.push_back(std::move(insn));
    }
    cs_free(insns, count);
    return out;
}

} // namespace core
