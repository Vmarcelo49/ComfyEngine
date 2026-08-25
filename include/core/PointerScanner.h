#pragma once

#include "core/TargetProcess.h"

#include <cstdint>
#include <vector>

namespace core {

struct PointerHit {
    uintptr_t baseAddress;
    int64_t offset;
    uintptr_t finalAddress;
};

class PointerScanner {
public:
    explicit PointerScanner(const TargetProcess &proc);

    std::vector<PointerHit> scan(uintptr_t target, int64_t maxOffset, bool writableOnly);

private:
    const TargetProcess &proc_;
};

} // namespace core
