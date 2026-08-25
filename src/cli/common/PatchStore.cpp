#include "PatchStore.h"
#include "Cli.h"

#include <nlohmann/json.hpp>

#include <fstream>

namespace cli {

PatchStore::PatchStore(std::string path) : path_(std::move(path)) {}

static nlohmann::json loadAll(const std::string &path) {
    std::ifstream f(path);
    if (!f.good()) return nlohmann::json::array();
    auto j = nlohmann::json::parse(f, nullptr, false);
    if (j.is_discarded() || !j.is_array()) return nlohmann::json::array();
    return j;
}

static void saveAll(const std::string &path, const nlohmann::json &arr) {
    std::ofstream f(path, std::ios::trunc);
    if (!f.good()) return;
    f << arr.dump(2);
}

std::vector<PatchRecord> PatchStore::list(pid_t pid) const {
    std::vector<PatchRecord> out;
    for (const auto &e : loadAll(path_)) {
        PatchRecord r;
        r.pid = e.value("pid", 0);
        r.address = static_cast<uintptr_t>(strtoull(e.value("address", "0").c_str(), nullptr, 0));
        for (const auto &b : e.value("original", std::vector<int>{})) {
            r.original.push_back(static_cast<uint8_t>(b));
        }
        if (pid != 0 && r.pid != pid) continue;
        out.push_back(std::move(r));
    }
    return out;
}

bool PatchStore::get(pid_t pid, uintptr_t address, PatchRecord &out) const {
    for (const auto &r : list()) {
        if (r.pid == pid && r.address == address) {
            out = r;
            return true;
        }
    }
    return false;
}

void PatchStore::put(const PatchRecord &record) {
    nlohmann::json arr = loadAll(path_);
    nlohmann::json entry = {{"pid", record.pid},
                            {"address", addrHex(record.address)},
                            {"original", record.original}};
    for (auto it = arr.begin(); it != arr.end(); ++it) {
        if (it->value("pid", 0) == record.pid &&
            strtoull(it->value("address", "0").c_str(), nullptr, 0) == record.address) {
            arr.erase(it);
            break;
        }
    }
    arr.push_back(entry);
    saveAll(path_, arr);
}

bool PatchStore::remove(pid_t pid, uintptr_t address) {
    nlohmann::json arr = loadAll(path_);
    bool removed = false;
    for (auto it = arr.begin(); it != arr.end(); ++it) {
        if (it->value("pid", 0) == pid &&
            strtoull(it->value("address", "0").c_str(), nullptr, 0) == address) {
            arr.erase(it);
            removed = true;
            break;
        }
    }
    if (removed) saveAll(path_, arr);
    return removed;
}

} // namespace cli
