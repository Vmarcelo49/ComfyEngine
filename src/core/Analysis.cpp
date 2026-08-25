#include "core/Analysis.h"
#include "core/ScalarCodec.h"

#include <algorithm>
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

std::unordered_map<uintptr_t, size_t> inboundPointerCounts(TargetProcess &proc,
                                                           const std::vector<uintptr_t> &sortedCandidates,
                                                           uintptr_t window) {
    std::unordered_map<uintptr_t, size_t> out;
    if (!proc.isAttached() || sortedCandidates.empty()) return out;
    auto bump = [&](uintptr_t v) {
        if (v == 0) return;
        uintptr_t lo = v > window ? v - window : 0;
        uintptr_t hi = v + window;
        auto it = std::lower_bound(sortedCandidates.begin(), sortedCandidates.end(), lo);
        for (; it != sortedCandidates.end() && *it <= hi; ++it) {
            ++out[*it];
        }
    };
    constexpr size_t kChunk = 64 * 1024;
    std::vector<uint8_t> buffer(kChunk + 8, 0);
    for (const auto &region : proc.regions()) {
        if (region.perms.find('r') == std::string::npos) continue;
        for (uintptr_t addr = region.start; addr < region.end; addr += kChunk) {
            size_t toRead = std::min(kChunk, region.end - addr);
            buffer.resize(toRead);
            if (!proc.readMemory(addr, buffer.data(), toRead)) continue;
            for (size_t off = 0; off + sizeof(uintptr_t) <= toRead; off += sizeof(uintptr_t)) {
                uintptr_t v = 0;
                memcpy(&v, buffer.data() + off, sizeof(v));
                bump(v);
            }
        }
    }
    return out;
}

double neighborCoherence(TargetProcess &proc, uintptr_t addr, const RegionIndex &index, size_t bytes) {
    std::vector<uint8_t> buf(bytes, 0);
    if (!proc.readMemory(addr, buf.data(), buf.size())) return 0.0;
    const size_t slots = buf.size() / 4;
    double score = 0.0;
    for (size_t i = 0; i < slots; ++i) {
        uint32_t u = 0;
        memcpy(&u, buf.data() + i * 4, 4);
        if (u == 0) {
            score += 0.25;
            continue;
        }
        int32_t iv = 0;
        float fv = 0.f;
        memcpy(&iv, &u, 4);
        memcpy(&fv, &u, 4);
        bool intOk = std::abs(static_cast<double>(iv)) < 1e8;
        bool floatOk = std::isfinite(fv) && std::fabs(fv) > 1e-30f && std::fabs(fv) < 1e9f;
        if (intOk && floatOk) score += 1.0;
        else if (intOk || floatOk) score += 0.6;
        else score -= 0.8;
    }
    for (size_t i = 0; i + 2 <= slots; i += 2) {
        uint64_t v = 0;
        memcpy(&v, buf.data() + i * 4, 8);
        if (v != 0 && index.looksLikePointer(static_cast<uintptr_t>(v))) score += 1.5;
    }
    return std::max(-8.0, score);
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

    std::unordered_map<uintptr_t, size_t> inbound;
    if (options.enableInbound) {
        inbound = inboundPointerCounts(proc, addresses, options.inboundWindow);
    }

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

        if (!asciiCandidate && !entry.pointerCandidate && hasBytes) {
            float fv = 0.f;
            double dv = 0.0;
            memcpy(&fv, buffer.data(), std::min(sizeof(fv), buffer.size()));
            memcpy(&dv, buffer.data(), std::min(sizeof(dv), buffer.size()));
            bool fClean = std::isfinite(fv) && std::fabs(fv) > options.floatMinAbs && std::fabs(fv) < options.floatMaxAbs;
            bool dClean = std::isfinite(dv) && std::fabs(dv) > options.doubleMinAbs && std::fabs(dv) < options.doubleMaxAbs;
            if (fClean) {
                entry.guessedType = ValueType::Float;
                score += options.floatScore;
            } else if (dClean) {
                entry.guessedType = ValueType::Double;
                score += options.doubleScore;
            }
        }

        size_t refs = 0;
        if (options.enableInbound) {
            auto it = inbound.find(addr);
            if (it != inbound.end()) refs = it->second;
        }
        entry.inboundPointers = refs;
        size_t capped = std::min(refs, options.inboundCap);
        score += options.inboundWeight * std::log2(1.0 + static_cast<double>(capped));

        entry.neighborScore = neighborCoherence(proc, addr, index, options.neighborBytes);
        score += options.neighborWeight * entry.neighborScore;

        if (refs >= options.corroborationMinRefs &&
            entry.neighborScore >= options.corroborationMinNeighbors) {
            score += options.structCorroborationBonus;
        }

        size_t align = defaultAlignment(displayType);
        if (align > 1 && addr % align == 0) score += options.alignmentBonus;

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
