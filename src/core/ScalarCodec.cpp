#include "core/ScalarCodec.h"

#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

namespace core {

size_t sizeForType(ValueType t) {
    switch (t) {
        case ValueType::Byte: return sizeof(int8_t);
        case ValueType::Int16: return sizeof(int16_t);
        case ValueType::Int32: return sizeof(int32_t);
        case ValueType::Int64: return sizeof(int64_t);
        case ValueType::Float: return sizeof(float);
        case ValueType::Double: return sizeof(double);
        case ValueType::ArrayOfByte:
        case ValueType::String:
            return 0;
    }
    return 0;
}

size_t defaultAlignment(ValueType t) {
    switch (t) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32: return 4;
        case ValueType::Int64: return 8;
        case ValueType::Float: return 4;
        case ValueType::Double: return 8;
        default: return 1;
    }
}

const char *typeToString(ValueType t) {
    switch (t) {
        case ValueType::Byte: return "Byte";
        case ValueType::Int16: return "2 Bytes";
        case ValueType::Int32: return "4 Bytes";
        case ValueType::Int64: return "8 Bytes";
        case ValueType::Float: return "Float";
        case ValueType::Double: return "Double";
        case ValueType::ArrayOfByte: return "AOB";
        case ValueType::String: return "String";
    }
    return "Unknown";
}

std::optional<ValueType> typeFromString(const std::string &label) {
    if (label == "Byte") return ValueType::Byte;
    if (label == "2 Bytes") return ValueType::Int16;
    if (label == "4 Bytes") return ValueType::Int32;
    if (label == "8 Bytes") return ValueType::Int64;
    if (label == "Float") return ValueType::Float;
    if (label == "Double") return ValueType::Double;
    if (label == "AOB") return ValueType::ArrayOfByte;
    if (label == "String") return ValueType::String;
    return std::nullopt;
}

double decodeRaw(uint64_t raw, ValueType t, bool *ok) {
    double value = 0.0;
    switch (t) {
        case ValueType::Byte: value = static_cast<double>(unpackRaw<int8_t>(raw)); break;
        case ValueType::Int16: value = static_cast<double>(unpackRaw<int16_t>(raw)); break;
        case ValueType::Int32: value = static_cast<double>(unpackRaw<int32_t>(raw)); break;
        case ValueType::Int64: value = static_cast<double>(unpackRaw<int64_t>(raw)); break;
        case ValueType::Float: value = static_cast<double>(unpackRaw<float>(raw)); break;
        case ValueType::Double: value = unpackRaw<double>(raw); break;
        default:
            if (ok) *ok = false;
            return 0.0;
    }
    if (ok) *ok = true;
    return value;
}

double decodeNumeric(const uint8_t *data, size_t len, ValueType t, bool *ok) {
    if (ok) *ok = false;
    if (!data || len == 0) return 0.0;
    auto readAs = [&](auto *dummy) -> double {
        using T = std::remove_pointer_t<decltype(dummy)>;
        if (len < sizeof(T)) return 0.0;
        T v{};
        memcpy(&v, data, sizeof(T));
        if (ok) *ok = true;
        return static_cast<double>(v);
    };
    switch (t) {
        case ValueType::Byte: return readAs(static_cast<int8_t *>(nullptr));
        case ValueType::Int16: return readAs(static_cast<int16_t *>(nullptr));
        case ValueType::Int32: return readAs(static_cast<int32_t *>(nullptr));
        case ValueType::Int64: return readAs(static_cast<int64_t *>(nullptr));
        case ValueType::Float: return readAs(static_cast<float *>(nullptr));
        case ValueType::Double: return readAs(static_cast<double *>(nullptr));
        default:
            return 0.0;
    }
}

template <typename T>
static std::string formatIntegral(T v) {
    char buf[32];
    if constexpr (sizeof(T) > 4) {
        snprintf(buf, sizeof(buf), "%" PRId64, static_cast<int64_t>(v));
    } else {
        snprintf(buf, sizeof(buf), "%d", static_cast<int>(v));
    }
    return buf;
}

std::string formatRawValue(uint64_t raw, ValueType t) {
    switch (t) {
        case ValueType::Byte: return formatIntegral(unpackRaw<int8_t>(raw));
        case ValueType::Int16: return formatIntegral(unpackRaw<int16_t>(raw));
        case ValueType::Int32: return formatIntegral(unpackRaw<int32_t>(raw));
        case ValueType::Int64: return formatIntegral(unpackRaw<int64_t>(raw));
        case ValueType::Float: {
            float v = unpackRaw<float>(raw);
            char buf[64];
            snprintf(buf, sizeof(buf), "%.6g", static_cast<double>(v));
            return buf;
        }
        case ValueType::Double: {
            double v = unpackRaw<double>(raw);
            char buf[128];
            snprintf(buf, sizeof(buf), "%.12g", v);
            return buf;
        }
        case ValueType::ArrayOfByte:
        case ValueType::String:
            return std::string();
    }
    return std::string();
}

std::string formatValueBytes(const uint8_t *data, size_t len, ValueType t) {
    if (!data || len == 0) return std::string();
    size_t sz = sizeForType(t);
    if (sz != 0 && len < sz) return std::string();
    switch (t) {
        case ValueType::Byte: return formatIntegral(*reinterpret_cast<const int8_t *>(data));
        case ValueType::Int16: return formatIntegral(*reinterpret_cast<const int16_t *>(data));
        case ValueType::Int32: return formatIntegral(*reinterpret_cast<const int32_t *>(data));
        case ValueType::Int64: return formatIntegral(*reinterpret_cast<const int64_t *>(data));
        case ValueType::Float: {
            float v;
            memcpy(&v, data, sizeof(v));
            char buf[64];
            snprintf(buf, sizeof(buf), "%.6g", static_cast<double>(v));
            return buf;
        }
        case ValueType::Double: {
            double v;
            memcpy(&v, data, sizeof(v));
            char buf[128];
            snprintf(buf, sizeof(buf), "%.12g", v);
            return buf;
        }
        case ValueType::ArrayOfByte: {
            std::string out;
            out.reserve(len * 3);
            for (size_t i = 0; i < len; ++i) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02x", data[i]);
                if (i) out.push_back(' ');
                out += buf;
            }
            return out;
        }
        case ValueType::String:
            return std::string(reinterpret_cast<const char *>(data), len);
    }
    return std::string();
}

std::optional<std::vector<uint8_t>> parseScalar(const std::string &text, ValueType t) {
    try {
        switch (t) {
            case ValueType::Byte: {
                int64_t v = std::stoll(text);
                int8_t vv = static_cast<int8_t>(v);
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&vv),
                                            reinterpret_cast<uint8_t *>(&vv) + sizeof(vv));
            }
            case ValueType::Int16: {
                int64_t v = std::stoll(text);
                int16_t vv = static_cast<int16_t>(v);
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&vv),
                                            reinterpret_cast<uint8_t *>(&vv) + sizeof(vv));
            }
            case ValueType::Int32: {
                int64_t v = std::stoll(text);
                int32_t vv = static_cast<int32_t>(v);
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&vv),
                                            reinterpret_cast<uint8_t *>(&vv) + sizeof(vv));
            }
            case ValueType::Int64: {
                int64_t v = std::stoll(text);
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&v),
                                            reinterpret_cast<uint8_t *>(&v) + sizeof(v));
            }
            case ValueType::Float: {
                size_t pos = 0;
                float v = std::stof(text, &pos);
                while (pos < text.size() && isspace(static_cast<unsigned char>(text[pos]))) ++pos;
                if (pos != text.size()) return std::nullopt;
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&v),
                                            reinterpret_cast<uint8_t *>(&v) + sizeof(v));
            }
            case ValueType::Double: {
                size_t pos = 0;
                double v = std::stod(text, &pos);
                while (pos < text.size() && isspace(static_cast<unsigned char>(text[pos]))) ++pos;
                if (pos != text.size()) return std::nullopt;
                return std::vector<uint8_t>(reinterpret_cast<uint8_t *>(&v),
                                            reinterpret_cast<uint8_t *>(&v) + sizeof(v));
            }
            case ValueType::ArrayOfByte:
            case ValueType::String:
                return std::nullopt;
        }
    } catch (...) {
        return std::nullopt;
    }
    return std::nullopt;
}

bool readScalar(TargetProcess &proc, uintptr_t address, ValueType t, std::vector<uint8_t> &out) {
    size_t sz = sizeForType(t);
    if (sz == 0) return false;
    out.resize(sz);
    if (!proc.readMemory(address, out.data(), sz)) {
        out.clear();
        return false;
    }
    return true;
}

bool writeScalarText(TargetProcess &proc, uintptr_t address, ValueType t, const std::string &text,
                     std::vector<uint8_t> *written) {
    auto bytes = parseScalar(text, t);
    if (!bytes) return false;
    if (!proc.writeMemory(address, bytes->data(), bytes->size())) return false;
    if (written) *written = *bytes;
    return true;
}

uintptr_t resolvePointerChain(TargetProcess &proc, uintptr_t base, const std::vector<int64_t> &offsets) {
    uintptr_t current = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        uintptr_t pointed = 0;
        if (!proc.readMemory(current, &pointed, sizeof(pointed))) return 0;
        current = pointed + static_cast<uintptr_t>(offsets[i]);
    }
    return current;
}

std::string ptraceHint() {
    std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
    int scope = -1;
    if (f.good()) {
        f >> scope;
    }
    if (scope > 0) {
        char buf[160];
        snprintf(buf, sizeof(buf),
                 "\nHint: ptrace_scope=%d; try 'echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope' or run as root.",
                 scope);
        return buf;
    }
    return std::string();
}

} // namespace core
