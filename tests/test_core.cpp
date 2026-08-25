#include "core/Analysis.h"
#include "core/AutoAssembler.h"
#include "core/CheatTable.h"
#include "core/Disassembler.h"
#include "core/ScalarCodec.h"
#include "core/TargetProcess.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        ++checks;                                                           \
        if (!(cond)) {                                                      \
            ++failures;                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                   \
    } while (0)

static void testScalarCodecNames() {
    CHECK(core::sizeForType(core::ValueType::Byte) == 1);
    CHECK(core::sizeForType(core::ValueType::Int16) == 2);
    CHECK(core::sizeForType(core::ValueType::Int32) == 4);
    CHECK(core::sizeForType(core::ValueType::Int64) == 8);
    CHECK(core::sizeForType(core::ValueType::Float) == 4);
    CHECK(core::sizeForType(core::ValueType::Double) == 8);
    CHECK(core::sizeForType(core::ValueType::ArrayOfByte) == 0);
    CHECK(core::defaultAlignment(core::ValueType::Float) == 4);
    CHECK(core::defaultAlignment(core::ValueType::Double) == 8);

    const core::ValueType all[] = {
        core::ValueType::Byte,        core::ValueType::Int16,       core::ValueType::Int32,
        core::ValueType::Int64,       core::ValueType::Float,       core::ValueType::Double,
        core::ValueType::ArrayOfByte, core::ValueType::String,
    };
    for (auto t : all) {
        auto parsed = core::typeFromString(core::typeToString(t));
        CHECK(parsed.has_value());
        CHECK(*parsed == t);
    }
    CHECK(!core::typeFromString("nonsense").has_value());
}

static void testScalarCodecParseFormat() {
    auto i32 = core::parseScalar("-42", core::ValueType::Int32);
    CHECK(i32.has_value() && i32->size() == 4);
    int32_t i32v = 0;
    if (i32) std::memcpy(&i32v, i32->data(), 4);
    CHECK(i32v == -42);

    auto u8 = core::parseScalar("200", core::ValueType::Byte);
    CHECK(u8.has_value() && u8->size() == 1);
    CHECK((*u8)[0] == 200);

    auto f = core::parseScalar("1.5", core::ValueType::Float);
    CHECK(f.has_value() && f->size() == 4);
    float fv = 0;
    if (f) std::memcpy(&fv, f->data(), 4);
    CHECK(fv == 1.5f);

    auto d = core::parseScalar("2.25e1", core::ValueType::Double);
    CHECK(d.has_value());
    double dv = 0;
    if (d) std::memcpy(&dv, d->data(), 8);
    CHECK(dv == 22.5);

    CHECK(!core::parseScalar("abc", core::ValueType::Int32).has_value());

    uint64_t raw = 0;
    float oneFive = 1.5f;
    std::memcpy(&raw, &oneFive, 4);
    CHECK(core::formatRawValue(raw, core::ValueType::Float) == "1.5");
    CHECK(core::decodeRaw(raw, core::ValueType::Float) == 1.5);

    uint64_t big = 0;
    int64_t bigV = -1234567890123LL;
    std::memcpy(&big, &bigV, 8);
    CHECK(core::formatRawValue(big, core::ValueType::Int64) == "-1234567890123");

    const uint8_t aob[2] = {0x90, 0x0F};
    CHECK(core::formatValueBytes(aob, 2, core::ValueType::ArrayOfByte) == "90 0f");

    bool ok = true;
    core::decodeRaw(0, core::ValueType::String, &ok);
    CHECK(!ok);

    const uint8_t strBytes[5] = {'h', 'e', 'l', 'l', 'o'};
    CHECK(core::formatValueBytes(strBytes, 5, core::ValueType::String) == "hello");

    CHECK(core::spikeThreshold(core::ValueType::Float) == 0.5);
    CHECK(core::spikeThreshold(core::ValueType::Double) == 1.0);
    CHECK(core::spikeThreshold(core::ValueType::Int32) == 10.0);
}

static void testAutoAssemblerParsing() {
    std::unordered_map<std::string, uintptr_t> symbols{{"game.so", 0x500000}};

    std::string err;
    auto patch = core::AutoAssembler::parseLine("patch 0x401000 90 90 c3", symbols, err);
    CHECK(patch.has_value());
    CHECK(patch->type == core::AutoAssembler::Command::Type::Patch);
    CHECK(patch->address == 0x401000);
    CHECK((patch->bytes == std::vector<uint8_t>{0x90, 0x90, 0xC3}));

    auto restore = core::AutoAssembler::parseLine("restore game.so+10", symbols, err);
    CHECK(restore.has_value());
    CHECK(restore->type == core::AutoAssembler::Command::Type::Restore);
    CHECK(restore->address == 0x50000A);

    auto negOffset = core::AutoAssembler::parseLine("patch game.so-4 00", symbols, err);
    CHECK(negOffset.has_value());
    CHECK(negOffset->address == 0x4FFFFC);

    CHECK(!core::AutoAssembler::parseLine("frobnicate 0x401000 90", symbols, err));
    CHECK(err.find("Unknown directive") != std::string::npos);
    CHECK(!core::AutoAssembler::parseLine("patch 0x401000", symbols, err));
    CHECK(err == "No bytes provided");
    CHECK(!core::AutoAssembler::parseLine("patch other.sym 00", symbols, err));
    CHECK(err.find("Unknown symbol") != std::string::npos);
    CHECK(!core::AutoAssembler::parseLine("patch 0x401000 zz", symbols, err));

    CHECK(core::AutoAssembler::parseLine("; comment", symbols, err) == std::nullopt);
    CHECK(core::AutoAssembler::parseLine("# comment", symbols, err) == std::nullopt);
    CHECK(core::AutoAssembler::parseLine("// comment", symbols, err) == std::nullopt);

    std::string wrapped = core::AutoAssembler::ensureEnableSection("patch 0x401000 90");
    CHECK(wrapped.find("[ENABLE]") == 0);
    CHECK(wrapped.find("[DISABLE]") != std::string::npos);

    std::string tpl = core::AutoAssembler::codeInjectionTemplate(0x401000, {0x01, 0x02});
    CHECK(tpl.find("patch 0x401000 90 90 90 90 90") != std::string::npos);
    CHECK(tpl.find("; original 01 02") != std::string::npos);
    CHECK(tpl.find("restore 0x401000") != std::string::npos);

    std::string aobTpl = core::AutoAssembler::aobInjectionTemplate({0xAA, 0xBB});
    CHECK(aobTpl.find("aobscanmodule(INJECT,$process,AA BB)") != std::string::npos);

    std::string script = core::AutoAssembler::patchScript(0x1234, {0x90}, false, nullptr);
    CHECK(script.find("patch 0x1234 90") != std::string::npos);
}

static void testCheatTableRoundTrip() {
    std::vector<core::CheatEntry> entries;
    core::CheatEntry e;
    e.address = 0x5555;
    e.type = core::ValueType::Int32;
    e.description = "health";
    e.isPointer = true;
    e.offsets = {0x10, -4};
    e.frozen = true;
    e.stored = {0x39, 0x05, 0x00, 0x00};
    entries.push_back(e);

    core::CheatEntry s;
    s.isScript = true;
    s.description = "nop script";
    s.scriptSource = "[ENABLE]\npatch 0x401000 90\n\n[DISABLE]\nrestore 0x401000\n";
    s.scriptActive = true;
    entries.push_back(s);

    core::TableSaveOptions saveOpts;
    saveOpts.includeOffsets = true;
    std::string json = core::CheatTable::serialize(entries, saveOpts);
    CHECK(json.find("\"entries\"") != std::string::npos);
    CHECK(json.find("health") != std::string::npos);
    CHECK(json.find("offsets") != std::string::npos);

    core::TableLoadOptions opts;
    opts.activateScripts = true;
    opts.loadPointerOffsets = true;
    auto back = core::CheatTable::deserialize(json, opts);
    CHECK(back.size() == 2);
    if (back.size() == 2) {
        CHECK(back[0].address == 0x5555);
        CHECK(back[0].type == core::ValueType::Int32);
        CHECK(back[0].description == "health");
        CHECK(back[0].isPointer);
        CHECK((back[0].offsets == std::vector<int64_t>{0x10, -4}));
        CHECK(back[0].frozen);
        CHECK((back[0].stored == std::vector<uint8_t>{0x39, 0x05, 0x00, 0x00}));
        CHECK(back[1].isScript);
        CHECK(back[1].scriptActive);
        CHECK(back[1].scriptSource.find("restore 0x401000") != std::string::npos);
    }

    std::string legacy =
        "{\"entries\":[{\"address\":\"0x1000\",\"type\":\"8 Bytes\",\"description\":\"d\","
        "\"pointer\":true,\"frozen\":false,\"valueBytes\":\"ff 00\"},{\"isScript\":true,"
        "\"description\":\"s\",\"script\":\"[ENABLE]\\n\",\"active\":true}]}";
    auto legacyOut = core::CheatTable::deserialize(legacy, {});
    CHECK(legacyOut.size() == 2);
    if (legacyOut.size() == 2) {
        CHECK(legacyOut[0].type == core::ValueType::Int64);
        CHECK(legacyOut[0].offsets.empty());
        CHECK(!legacyOut[1].scriptActive);
    }

    auto garbage = core::CheatTable::deserialize("not json at all", {});
    CHECK(garbage.empty());
}

static void testDisassembler() {
    core::Disassembler dis;
    if (!dis.valid()) {
        fprintf(stderr, "capstone unavailable; skipping disasm checks\n");
        return;
    }
    const uint8_t code[] = {0x90, 0x90, 0xC3};
    auto insns = dis.disassemble(code, sizeof(code), 0x1000);
    CHECK(insns.size() == 3);
    if (insns.size() == 3) {
        CHECK(insns[0].mnemonic == "nop");
        CHECK(insns[1].mnemonic == "nop");
        CHECK(insns[2].mnemonic == "ret");
        CHECK(insns[0].address == 0x1000);
        CHECK(insns[2].address == 0x1002);
    }
    const uint8_t movCode[] = {0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3};
    auto insns2 = dis.disassemble(movCode, sizeof(movCode), 0);
    CHECK(insns2.size() == 2);
    if (insns2.size() == 2) {
        CHECK(insns2[0].mnemonic == "mov");
        CHECK(insns2[0].operands.find("0x1337") != std::string::npos);
    }
}

static void testIntegrationReadWrite(const char *childPath) {
    int fds[2];
    if (pipe(fds) != 0) return;
    pid_t child = fork();
    if (child == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execl(childPath, childPath, static_cast<char *>(nullptr));
        _exit(127);
    }
    close(fds[1]);

    FILE *reader = fdopen(fds[0], "r");
    uintptr_t xAddr = 0;
    uintptr_t pAddr = 0;
    char line[128];
    while (fgets(line, sizeof(line), reader)) {
        unsigned long long v = 0;
        if (sscanf(line, "X=%llx", &v) == 1) xAddr = static_cast<uintptr_t>(v);
        else if (sscanf(line, "P=%llx", &v) == 1) pAddr = static_cast<uintptr_t>(v);
        if (xAddr && pAddr) break;
    }

    if (!xAddr || !pAddr) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        if (reader) fclose(reader);
        CHECK(false);
        return;
    }

    core::TargetProcess proc;
    if (!proc.attach(child)) {
        fprintf(stderr, "attach unavailable (yama?); skipping integration\n");
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        if (reader) fclose(reader);
        return;
    }
    CHECK(proc.isAttached());

    std::vector<uint8_t> val;
    CHECK(core::readScalar(proc, xAddr, core::ValueType::Int32, val));
    int32_t v32 = 0;
    if (!val.empty()) std::memcpy(&v32, val.data(), 4);
    CHECK(v32 == 1337);

    CHECK(core::writeScalarText(proc, xAddr, core::ValueType::Int32, "4242"));

    CHECK(core::readScalar(proc, xAddr, core::ValueType::Int32, val));
    v32 = 0;
    if (!val.empty()) std::memcpy(&v32, val.data(), 4);
    CHECK(v32 == 4242);

    CHECK(core::resolvePointerChain(proc, pAddr, {0}) == xAddr);

    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    if (reader) fclose(reader);
}

int main(int argc, char **argv) {
    testScalarCodecNames();
    testScalarCodecParseFormat();
    testAutoAssemblerParsing();
    testCheatTableRoundTrip();
    testDisassembler();
    testIntegrationReadWrite(argc > 1 ? argv[1] : "./test_target_child");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
