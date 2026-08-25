#pragma once

#include "core/MemoryScanner.h"
#include "core/TargetProcess.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace core {

struct CheatEntry {
    uintptr_t address{0};
    ValueType type{ValueType::Int32};
    std::string description;
    bool isPointer{false};
    std::vector<int64_t> offsets;
    bool frozen{false};
    std::vector<uint8_t> stored;
    bool isScript{false};
    bool scriptActive{false};
    std::string scriptSource;
};

struct TableSaveOptions {
    bool includeOffsets{false};
};

struct TableLoadOptions {
    bool activateScripts{false};
    bool loadPointerOffsets{false};
};

class CheatTable {
public:
    explicit CheatTable(TargetProcess &proc);

    void setEntries(std::vector<CheatEntry> entries);
    const std::vector<CheatEntry> &entries() const { return entries_; }
    std::vector<CheatEntry> &entries() { return entries_; }

    void enforceOnce();

    void startFreezePump(std::chrono::milliseconds interval = std::chrono::milliseconds(50));
    void stopFreezePump();
    bool pumpRunning() const { return pumpRunning_.load(); }

    bool saveToFile(const std::string &path, const TableSaveOptions &options = {}) const;
    bool loadFromFile(const std::string &path, const TableLoadOptions &options = {});

    static std::string serialize(const std::vector<CheatEntry> &entries, const TableSaveOptions &options = {});
    static std::vector<CheatEntry> deserialize(const std::string &jsonText, const TableLoadOptions &options = {});

private:
    TargetProcess &proc_;
    std::vector<CheatEntry> entries_;

    mutable std::mutex mutex_;
    std::thread thread_;
    std::condition_variable cv_;
    std::atomic<bool> pumpRunning_{false};

    void pumpLoop(std::chrono::milliseconds interval);
};

} // namespace core
