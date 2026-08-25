#pragma once

#include "core/MemoryScanner.h"
#include "core/TargetProcess.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

struct RegionIndex {
    std::vector<MemoryRegion> regions;

    const MemoryRegion *find(uintptr_t address) const {
        for (const auto &region : regions) {
            if (address >= region.start && address < region.end) return &region;
        }
        return nullptr;
    }
    bool looksLikePointer(uintptr_t value) const {
        if (value == 0) return false;
        const MemoryRegion *region = find(value);
        if (!region) return false;
        return region->perms.find('r') != std::string::npos;
    }
};

struct MetaEntry {
    double score{0.0};
    ValueType guessedType{ValueType::Int32};
    bool pointerCandidate{false};
    std::string groupLabel;
    double neighborScore{0.0};
    size_t inboundPointers{0};
};

struct MetaOptions {
    size_t limit{2048};
    uintptr_t groupGap{32};
    double clusterBonus{10.0};
    int stringPrintableMin{6};
    double stringScore{25.0};
    double pointerScore{40.0};
    float floatMaxAbs{1e6f};
    double floatMinAbs{1e-30f};
    double floatScore{15.0};
    double doubleMaxAbs{1e12};
    double doubleMinAbs{1e-25};
    double doubleScore{12.0};
    double writableBonus{5.0};
    double execPenalty{-3.0};
    double alignmentBonus{2.0};
    bool enableInbound{true};
    uintptr_t inboundWindow{64};
    double inboundWeight{12.0};
    size_t neighborBytes{64};
    double neighborWeight{2.0};
};

double spikeThreshold(ValueType t);

std::unordered_map<uintptr_t, size_t> inboundPointerCounts(TargetProcess &proc,
                                                           const std::vector<uintptr_t> &sortedCandidates,
                                                           uintptr_t window);

double neighborCoherence(TargetProcess &proc, uintptr_t addr, const RegionIndex &index, size_t bytes);

std::unordered_map<uintptr_t, MetaEntry> analyzeMetaResults(TargetProcess &proc,
                                                            const std::vector<ScanResult> &results,
                                                            ValueType displayType,
                                                            const MetaOptions &options = {});

std::vector<uintptr_t> diffSnapshot(const std::unordered_map<uintptr_t, uint64_t> &snapshot,
                                    const std::vector<ScanResult> &results);

} // namespace core
