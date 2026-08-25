#include "core/CheatTable.h"
#include "core/ScalarCodec.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>

namespace core {

namespace {

std::string bytesToHexSpaced(const std::vector<uint8_t> &bytes) {
    std::string out;
    out.reserve(bytes.size() * 3);
    for (size_t i = 0; i < bytes.size(); ++i) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        if (i) out.push_back(' ');
        out += buf;
    }
    return out;
}

std::vector<uint8_t> hexSpacedToBytes(const std::string &hex) {
    std::istringstream iss(hex);
    std::vector<uint8_t> out;
    std::string tok;
    while (iss >> tok) {
        try {
            out.push_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
        } catch (...) {
            break;
        }
    }
    return out;
}

} // namespace

CheatTable::CheatTable(TargetProcess &proc) : proc_(proc) {}

void CheatTable::setEntries(std::vector<CheatEntry> entries) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_ = std::move(entries);
}

void CheatTable::enforceOnce() {
    std::vector<CheatEntry> snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &e : entries_) {
            if (!e.frozen || e.isScript || e.stored.empty()) continue;
            snapshot.push_back(e);
        }
    }
    for (const auto &e : snapshot) {
        uintptr_t effectiveAddr = e.address;
        if (e.isPointer && !e.offsets.empty()) {
            effectiveAddr = resolvePointerChain(proc_, e.address, e.offsets);
        }
        if (effectiveAddr != 0) {
            proc_.writeMemory(effectiveAddr, e.stored.data(), e.stored.size());
        }
    }
}

void CheatTable::startFreezePump(std::chrono::milliseconds interval) {
    bool expected = false;
    if (!pumpRunning_.compare_exchange_strong(expected, true)) return;
    thread_ = std::thread([this, interval]() { pumpLoop(interval); });
}

void CheatTable::stopFreezePump() {
    if (!pumpRunning_.exchange(false)) return;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void CheatTable::pumpLoop(std::chrono::milliseconds interval) {
    while (pumpRunning_.load()) {
        enforceOnce();
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, interval, [this]() { return !pumpRunning_.load(); });
    }
}

std::string CheatTable::serialize(const std::vector<CheatEntry> &entries, const TableSaveOptions &options) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &w : entries) {
        nlohmann::json o = nlohmann::json::object();
        if (w.isScript) {
            o["isScript"] = true;
            o["description"] = w.description;
            o["script"] = w.scriptSource;
            o["active"] = w.scriptActive;
        } else {
            char addrBuf[32];
            snprintf(addrBuf, sizeof(addrBuf), "0x%llx", static_cast<unsigned long long>(w.address));
            o["address"] = addrBuf;
            o["type"] = typeToString(w.type);
            o["description"] = w.description;
            o["pointer"] = w.isPointer;
            o["frozen"] = w.frozen;
            o["valueBytes"] = bytesToHexSpaced(w.stored);
            if (options.includeOffsets && !w.offsets.empty()) {
                nlohmann::json offs = nlohmann::json::array();
                for (int64_t off : w.offsets) offs.push_back(off);
                o["offsets"] = offs;
            }
        }
        arr.push_back(o);
    }
    nlohmann::json root = nlohmann::json::object();
    root["entries"] = arr;
    return root.dump(4);
}

std::vector<CheatEntry> CheatTable::deserialize(const std::string &jsonText, const TableLoadOptions &options) {
    std::vector<CheatEntry> out;
    nlohmann::json root = nlohmann::json::parse(jsonText, nullptr, false);
    if (root.is_discarded() || !root.is_object()) return out;
    auto it = root.find("entries");
    if (it == root.end() || !it->is_array()) return out;
    for (const auto &val : *it) {
        if (!val.is_object()) continue;
        CheatEntry w;
        auto scriptIt = val.find("isScript");
        if (scriptIt != val.end() && scriptIt->is_boolean() && scriptIt->get<bool>()) {
            w.isScript = true;
            if (auto d = val.find("description"); d != val.end() && d->is_string())
                w.description = d->get<std::string>();
            if (auto s = val.find("script"); s != val.end() && s->is_string())
                w.scriptSource = s->get<std::string>();
            w.scriptActive = false;
            if (options.activateScripts) {
                if (auto a = val.find("active"); a != val.end() && a->is_boolean())
                    w.scriptActive = a->get<bool>();
            }
            out.push_back(std::move(w));
            continue;
        }
        auto addrIt = val.find("address");
        if (addrIt == val.end() || !addrIt->is_string()) continue;
        uintptr_t addr = 0;
        {
            const std::string &addrStr = addrIt->get_ref<const std::string &>();
            errno = 0;
            char *end = nullptr;
            addr = std::strtoull(addrStr.c_str(), &end, 0);
            if (end == addrStr.c_str()) addr = 0;
        }
        if (addr == 0) continue;
        w.address = addr;
        ValueType type = ValueType::Int32;
        if (auto t = val.find("type"); t != val.end() && t->is_string()) {
            if (auto parsed = typeFromString(t->get<std::string>())) type = *parsed;
        }
        w.type = type;
        if (auto d = val.find("description"); d != val.end() && d->is_string())
            w.description = d->get<std::string>();
        if (auto p = val.find("pointer"); p != val.end() && p->is_boolean())
            w.isPointer = p->get<bool>();
        if (auto f = val.find("frozen"); f != val.end() && f->is_boolean())
            w.frozen = f->get<bool>();
        if (auto v = val.find("valueBytes"); v != val.end() && v->is_string())
            w.stored = hexSpacedToBytes(v->get<std::string>());
        if (options.loadPointerOffsets) {
            if (auto offs = val.find("offsets"); offs != val.end() && offs->is_array()) {
                for (const auto &offVal : *offs) {
                    if (offVal.is_number_integer())
                        w.offsets.push_back(offVal.get<int64_t>());
                    else if (offVal.is_number_unsigned())
                        w.offsets.push_back(static_cast<int64_t>(offVal.get<uint64_t>()));
                }
            }
        }
        out.push_back(std::move(w));
    }
    return out;
}

bool CheatTable::saveToFile(const std::string &path, const TableSaveOptions &options) const {
    std::string text;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        text = serialize(entries_, options);
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.good()) return false;
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    return f.good();
}

bool CheatTable::loadFromFile(const std::string &path, const TableLoadOptions &options) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    auto loaded = deserialize(ss.str(), options);
    if (loaded.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    entries_ = std::move(loaded);
    return true;
}

} // namespace core
