#include "core/Analysis.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>

namespace core {

double spikeThreshold(ValueType t) {
    switch (t) {
        case ValueType::Float: return 0.5;
        case ValueType::Double: return 1.0;
        default: return 10.0;
    }
}

std::unordered_map<uintptr_t, MetaEntry> analyzeMetaResults(TargetProcess &proc,
                                                            const std::vector<ScanResult> &results,
                                                            ValueType displayType,
                                                            const MetaOptions &options) {
    std::unordered_map<uintptr_t, MetaEntry> out;
    if (!proc.isAttached() || results.empty()) return out;
    RegionIndex index{proc.regions()};

    size_t limit = results.size() < options.limit ? results.size() : options.limit;
    std::vector<uintptr_t> addresses;
    addresses.reserve(limit);
    for (size_t i = 0; i < limit; ++i) addresses.push_back(results[i].address);
    std::sort(addresses.begin(), addresses.end());

    std::vector<uintptr_t> groupBuffer;
    auto flushGroup = [&]() {
        if (groupBuffer.size() > 1) {
            char label[96];
            snprintf(label, sizeof(label), "Cluster 0x%llx (%zu entries)",
                     static_cast<unsigned long long>(groupBuffer.front()), groupBuffer.size());
            for (auto addr : groupBuffer) out[addr].groupLabel = label;
        }
        groupBuffer.clear();
    };
    uintptr_t previous = 0;
    for (uintptr_t addr : addresses) {
        if (groupBuffer.empty() || addr - previous <= options.groupGap) {
            groupBuffer.push_back(addr);
        } else {
            flushGroup();
            groupBuffer.push_back(addr);
        }
        previous = addr;
    }
    flushGroup();

    for (size_t i = 0; i < limit; ++i) {
        uintptr_t addr = results[i].address;
        MetaEntry &entry = out[addr];
        entry.guessedType = displayType;
        double score = 0.0;
        std::array<unsigned char, 16> buffer{};
        bool hasBytes = proc.readMemory(addr, buffer.data(), buffer.size());
        bool asciiCandidate = false;
        if (hasBytes) {
            int printable = 0;
            for (unsigned char ch : buffer) {
                if (ch == 0) continue;
                if (ch >= 32 && ch <= 126) ++printable;
            }
            if (printable >= options.stringPrintableMin) {
                asciiCandidate = true;
                score += options.stringScore;
                entry.guessedType = ValueType::String;
            }
        }

        if (hasBytes && buffer.size() >= sizeof(uintptr_t)) {
            uintptr_t possiblePtr = 0;
            std::memcpy(&possiblePtr, buffer.data(), sizeof(uintptr_t));
            if (index.looksLikePointer(possiblePtr)) {
                entry.pointerCandidate = true;
                score += options.pointerScore;
            }
        }

        if (!asciiCandidate && hasBytes) {
            float fv = 0.f;
            double dv = 0.0;
            memcpy(&fv, buffer.data(), std::min(sizeof(fv), buffer.size()));
            memcpy(&dv, buffer.data(), std::min(sizeof(dv), buffer.size()));
            if (std::isfinite(fv) && std::abs(fv) < options.floatMaxAbs) {
                entry.guessedType = ValueType::Float;
                score += options.floatScore;
            } else if (std::isfinite(dv) && std::abs(dv) < options.doubleMaxAbs) {
                entry.guessedType = ValueType::Double;
                score += options.doubleScore;
            }
        }

        if (!entry.groupLabel.empty()) score += options.clusterBonus;
        if (const MemoryRegion *region = index.find(addr)) {
            if (region->perms.find('w') != std::string::npos) score += options.writableBonus;
            if (region->perms.find('x') != std::string::npos) score += options.execPenalty;
        }

        entry.score = score;
    }
    return out;
}

std::vector<uintptr_t> diffSnapshot(const std::unordered_map<uintptr_t, uint64_t> &snapshot,
                                    const std::vector<ScanResult> &results) {
    std::vector<uintptr_t> changed;
    for (const auto &r : results) {
        auto it = snapshot.find(r.address);
        if (it != snapshot.end() && it->second != r.raw) {
            changed.push_back(r.address);
        }
    }
    return changed;
}

} // namespace core
