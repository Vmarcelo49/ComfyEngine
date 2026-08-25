#include "core/PointerScanner.h"

#include <cstring>

namespace core {

PointerScanner::PointerScanner(const TargetProcess &proc) : proc_(proc) {}

std::vector<PointerHit> PointerScanner::scan(uintptr_t target, int64_t maxOffset, bool writableOnly) {
    std::vector<PointerHit> hits;
    if (maxOffset <= 0) return hits;
    constexpr size_t kChunk = 64 * 1024;
    std::vector<uint8_t> buffer(kChunk);
    for (const auto &region : proc_.regions()) {
        if (region.perms.find('r') == std::string::npos) continue;
        if (writableOnly && region.perms.find('w') == std::string::npos) continue;
        uintptr_t start = region.start;
        uintptr_t end = region.end;
        for (uintptr_t addr = start; addr + sizeof(uintptr_t) <= end; addr += kChunk) {
            size_t toRead = std::min(kChunk, end - addr);
            buffer.resize(toRead);
            if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
            for (size_t offset = 0; offset + sizeof(uintptr_t) <= toRead; offset += sizeof(uintptr_t)) {
                uintptr_t val = 0;
                std::memcpy(&val, buffer.data() + offset, sizeof(uintptr_t));
                if (val == 0) continue;
                int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(val);
                if (diff >= -maxOffset && diff <= maxOffset) {
                    PointerHit hit;
                    hit.baseAddress = addr + offset;
                    hit.offset = diff;
                    hit.finalAddress = val + diff;
                    hits.push_back(hit);
                }
            }
        }
    }
    return hits;
}

} // namespace core
