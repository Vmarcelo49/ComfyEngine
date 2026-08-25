#pragma once

#include "core/MemoryScanner.h"
#include "core/TargetProcess.h"

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace core {

size_t sizeForType(ValueType t);
size_t defaultAlignment(ValueType t);
const char *typeToString(ValueType t);
std::optional<ValueType> typeFromString(const std::string &label);

template <typename T>
T unpackRaw(uint64_t raw) {
    T value{};
    memcpy(&value, &raw, sizeof(T));
    return value;
}

double decodeRaw(uint64_t raw, ValueType t, bool *ok = nullptr);
double decodeNumeric(const uint8_t *data, size_t len, ValueType t, bool *ok = nullptr);

std::string formatRawValue(uint64_t raw, ValueType t);
std::string formatValueBytes(const uint8_t *data, size_t len, ValueType t);

std::optional<std::vector<uint8_t>> parseScalar(const std::string &text, ValueType t);

bool readScalar(TargetProcess &proc, uintptr_t address, ValueType t, std::vector<uint8_t> &out);
bool writeScalarText(TargetProcess &proc, uintptr_t address, ValueType t, const std::string &text,
                     std::vector<uint8_t> *written = nullptr);

uintptr_t resolvePointerChain(TargetProcess &proc, uintptr_t base, const std::vector<int64_t> &offsets);

std::string ptraceHint();

} // namespace core
