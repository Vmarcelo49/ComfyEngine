#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cli {

struct PatchRecord {
    pid_t pid{0};
    uintptr_t address{0};
    std::vector<uint8_t> original;
};

class PatchStore {
public:
    explicit PatchStore(std::string path);

    std::vector<PatchRecord> list(pid_t pid = 0) const;
    bool get(pid_t pid, uintptr_t address, PatchRecord &out) const;
    void put(const PatchRecord &record);
    bool remove(pid_t pid, uintptr_t address);

private:
    std::string path_;
};

} // namespace cli
