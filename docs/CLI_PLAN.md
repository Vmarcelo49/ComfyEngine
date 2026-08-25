# ComfyEngine CLI Mode — Master Plan

**Feature:** full headless CLI (`comfy` + `comfyd`) exposing 100% of ComfyEngine's features so AI agents (and scripts) can drive the entire toolchain: process attach, memory scanning, watchlist/freeze, patching, Auto Assembler, AoB injection, pointer scanning, debug watchpoints, disassembly, and cheat tables.

**Status:** plan / not started
**Principle:** *one engine, two frontends.* All feature logic lives in `src/core`; GUI and CLI are thin views over it.

---

## Table of Contents
1. [Design goals](#1-design-goals)
2. [Current architecture inventory](#2-current-architecture-inventory)
3. [Deep audit — what exists and where](#3-deep-audit--what-exists-and-where)
4. [Reference: file formats & protocols](#4-reference-file-formats--protocols)
5. [Target architecture](#5-target-architecture)
6. [CLI command specification](#6-cli-command-specification)
7. [Wire protocol (daemon)](#7-wire-protocol-daemon)
8. [Output contract for agents](#8-output-contract-for-agents)
9. [Phase breakdown](#9-phase-breakdown)
10. [Testing strategy](#10-testing-strategy)
11. [Risks & mitigations](#11-risks--mitigations)
12. [Open questions](#12-open-questions)

---

## 1. Design Goals

1. **Full parity.** Every GUI capability reachable from the CLI. If a GUI-only code path blocks a feature, extract it to core rather than reimplement.
2. **Agent-first ergonomics.**
   - `--json` on every command; stable, documented schemas.
   - Self-describing API: `comfy schema` dumps every command/arg/type/exit-code as JSON so an agent can bootstrap with zero documentation.
   - Bounded output (pagination/limits on result sets) so scans never flood a model context.
   - NDJSON event streams for long-running things (monitors, watchpoints).
3. **Stateful where required.** Scan result sets, freeze enforcement, and debug-watch sessions are inherently stateful → small daemon owning them; everything else works as stateless one-shots.
4. **Zero regression for the GUI.** Phases are refactors first; GUI keeps building and behaving identically.
5. **Safe by default.** Destructive ops gated by explicit flags; `--dry-run` everywhere writes happen; daemon socket restricted to the same uid.

---

## 2. Current Architecture Inventory

Repo layout today:

```
include/core/          Qt-free engine headers
  TargetProcess.h      ptrace + /proc/<pid>/mem + process_vm_writev; regions(),
                       threads(), readMemory/writeMemory, allocateMemory/freeMemory,
                       setExecutionPointer/getExecutionPointer, remoteCall
  MemoryScanner.h      ValueType{Byte,Int16,Int32,Int64,Float,Double,ArrayOfByte,String}
                       ScanMode{Exact,UnknownInitial,Changed,Unchanged,Increased,
                       Decreased,GreaterThan,LessThan,Between,Aob}
                       ScanParams{type,mode,value1,value2,startAddress,endAddress,
                       alignment,requireWritable,requireExecutable,hexInput,
                       skipMaskedRegions}
                       firstScan/nextScan/requestCancel/resetCancel/estimateWork/
                       setProgressSink/results()/restoreResults/reset/parseAobPattern;
                       shadow-copy machinery for UnknownInitial scans
  CodeInjector.h       patchBytes/restore/safePatch/allocateRemote/injectJmp/remoteCall;
                       patches_ map = original-bytes undo store
  DebugWatch.h         DebugWatchSession: hardware watchpoints via external ce_watch
                       child; WatchType{Writes,Accesses}; snapshot(); static
                       writeViaWatcher()
  ProcessEnumerator.h  list() of {pid,name,cmdline}

src/core/              implementations (all Qt-free)
src/gui/               MainWindow (~3.5k lines) + dialogs; FEATURE LOGIC TRAPPED HERE
ce_watch/              helper process: hardware watchpoint watcher (plain C++, non-Qt),
                       fd-based line protocol
testgame/              Qt test target with known globals + pointer chain fixture
test_watch.c           plain-C alternative test target
```

Build: CMake ≥ 3.16, C++17, Qt6 Widgets, Capstone (required by `src/CMakeLists.txt:34-37`). Binary at `build/src/comfyengine`. Tests via `ctest` + internal `./build/test_watch`.

Key existing facts that shape the design:
- **`src/core` is already 100% Qt-free** — the CLI can link it directly with no Qt dependency.
- Scans are **synchronous** in `MemoryScanner`; the GUI merely wraps them in `QThread` (MainWindow.cpp:1577–1618). A headless caller invokes them directly and uses `setProgressSink` + `requestCancel` for progress/Ctrl-C.
- The ce_watch spawn path is **not Qt**: `fork()`+`execv()` in `DebugWatch.cpp:172–290`.
- Capstone is optional inside ce_watch events only (`HAVE_CAPSTONE`, Watcher.cpp:71–76, :338–352); the memory viewer requires it.

---

## 3. Deep Audit — What Exists and Where

All paths relative to repo root. This section is the extraction map; nothing here needs to be rediscovered during implementation.

### 3.1 Already clean (use as-is from CLI)

| Capability | Location | Notes |
|---|---|---|
| Process enumeration | `ProcessEnumerator::list()` | pid/name/cmdline |
| Attach/detach, RW memory | `TargetProcess` | yama/ptrace constraints apply (see 3.8) |
| Region & thread listing | `TargetProcess::regions()/listThreads()` | perms + path per region |
| Full scan workflow | `MemoryScanner` | all modes/types, shadow copy, cancel, progress sink |
| Byte patching w/ undo | `CodeInjector::patchBytes/restore` | original bytes snapshotted into `patches_` (CodeInjector.cpp:13–23, :62–68) |
| Remote alloc / jmp / call | `CodeInjector::allocateRemote/injectJmp/remoteCall`, `TargetProcess::remoteCall` | currently unused by GUI; free wins for CLI |
| Hardware watchpoints | `DebugWatchSession` + `ce_watch` | see protocol in §4.3 |

### 3.2 Watchlist / cheat table (trapped in MainWindow)

Data model: `struct WatchEntry` — include/gui/MainWindow.h:192–205
`{address, ValueType type, QString description, bool isPointer, vector<int64_t> offsets, bool frozen, QByteArray stored/last/prev, bool isScript, bool scriptActive, QString scriptSource}`
→ Extract verbatim to core; swap `QString/QByteArray` for `std::string/std::vector<uint8_t>`.

Engine logic to extract:

- **Freeze enforcement pump** — lambda on `freezeTimer_`, MainWindow.cpp:297–311: every 50 ms iterate watches, resolve pointer chain, re-write `stored` bytes via `writeMemory`. Loop body is pure engine logic; only cadence is QTimer. Started/stopped from: onAddWatch :2034–2039, onUpdateWatchValue :2114–2117, onLoadTable :2214–2218, freeze checkbox handlers :1170–1185, cellChanged handler :1298–1312. → becomes a `std::thread` + condition-variable tick inside `core::CheatTable`.
- **Pointer-chain resolution** — `MainWindow::resolvePointerChain(base, offsets)` MainWindow.cpp:2448–2457: reads pointer per step via `readMemory`, adds offset. Zero Qt. Used at :304–305 and :1865–1866. Cleanest single extraction. Note: watch entries created from the pointer scanner dialog (MainWindow.cpp:2991–3004) set `isPointer=true` but leave `offsets` empty → resolves to base unchanged (existing quirk; preserve or fix explicitly).
- **Typed scalar read/write/parse/format** — the giant `switch(ValueType)` blocks are copy-pasted **six times**: onModifyValue :1931–1997, onAddWatch :2019–2031, onUpdateWatchValue :2065–2107, refreshWatchValues :1875–1900, refreshResultValues :2350–2402, updateTrackedEntries :2652–2673. Plus anonymous-namespace helpers MainWindow.cpp: parseAddress :96–100, parseHexBytes :102–111, typeToString :113–125 (canonical labels `"Byte","2 Bytes","4 Bytes","8 Bytes","Float","Double","AOB","String"`), unpackRaw :127–132, formatRawValue :134–153, formatValue :155–182; members decodeNumeric/decodeRaw declared MainWindow.h:112–113. → one `core::ScalarCodec`.
- **Scan history / undo** — `scanHistory_` capped at 1 level: recordScanSnapshot :3077–3085, resetScanHistory :3087–3090, updateUndoState :3092–3096, onUndoScan :1698–1705 → `scanner_->restoreResults()` (already core, MemoryScanner.h:68). Only the history container lives GUI-side.
- **Snapshot compare ("track changes")** — recordSnapshot :2691–2702 (results → addr→raw map), compareSnapshot :2704–2735 (diff current vs snapshot into tracked sets). Pure map logic wrapped in QMessageBoxes.
- **Per-tick change detection** — refreshResultValues :2301–2427: maintains `liveValues_`, computes `changedAddresses_` + `spikedAddresses_` (spike thresholds: Float 0.5, Double 1.0, else 10.0 — lambda :2331–2337), spark timestamps showSpark :3134–3137. Qt-coupled part: polls only *visible* rows via viewport hit-testing (:2306–2323) — headless must poll all results or an explicit address set instead. updateTrackedEntries :2642–2689 populates the tracking tree (view concern).
- **Meta-analysis of scan results** — analyzeMetaResults :3139–3229, heuristic scoring over ≤2048 sorted addresses:
  - cluster grouping: gap ≤ 32 bytes → group label, +10 score (:3154–3175, :3220)
  - ≥6 printable ASCII bytes in first 16 → String guess, +25 (:3184–3194)
  - first 8 bytes pass `looksLikePointer` (:3231–3236 = value maps to readable region via `regionFor` :3238–3243) → pointer candidate, +40 (:3197–3204)
  - finite float < 1e6 → +15; finite double < 1e12 → +12 (:3206–3218)
  - region perms: 'w' +5, 'x' −3 (:3221–3224)
  - Outputs `metaScores_/guessedTypes_/metaGroups_/pointerCandidates_` (MainWindow.h:258–261); rendering in resultData :2459–2514 and metaSummary :3245–3264 stays GUI. Scoring itself is pure engine logic.
- **AA-script table rows** — onScriptSubmitted :3026–3034 stores scripts as watch rows; setScriptState :3036–3050 executes them **through a hidden `AutoAssemblerDialog` instance** (`ensureAutoAsmRunner` :3017–3024). Biggest blocker: headless needs `core::AutoAssembler::executeScriptText` (§3.3).

Qt-coupled view code (stays): ScanResultsModel :199–253, populateWatchList :1783–1851, timers, dialogs, QSettings persistence :3286–3369.

### 3.3 Auto Assembler (trapped in a QDialog)

All parser internals already use `std::string`/`std::istringstream`; only signatures/errors/logs are QString.

Functions (AutoAssemblerDialog.cpp): parseLine :106–150, parseSections :152–282, applyCommands/restoreCommands :284–301, parseAddressWithSymbols :311–344, scanAob :346–426, collectModuleBases :428–443, executeScriptText :489–507, template generation insertTemplate :549–607, buildScriptFromEditor :613–620.

Supported language (complete list):
- `[ENABLE]` / `[DISABLE]` sections (case-insensitive, :168–175). Missing header ⇒ whole text treated as ENABLE (buildScriptFromEditor :613–620). No DISABLE commands ⇒ disable falls back to restoring originals.
- `patch <addr> <hex bytes...>` (:115, :133–148)
- `restore <addr>` (:117–118)
- `aobscan(name, pattern...)` / `aobscanmodule(name, module, pattern...)` (:177–259): paren or whitespace forms; wildcards `??`, `?`, `**` (:382–384); module filter matches basename or `$process` (:361–374); chunked 64 KB readable-region scan, first match wins (:399–425); result registered as symbol (:250).
- Address operands: hex literal (base-0) or `symbol+offset`/`symbol-offset` (parseAddressWithSymbols :311–344); symbols preloaded with module basenames → lowest region start (collectModuleBases :428–443).
- Comments: `;`, `#`, `//` (:109–110).

NOT supported (vs real Cheat Engine AA): `alloc`, `dealloc`, `registersymbol`, `label`, `newmem`, `code/inject` blocks, `createthread`, actual assembly. It is a byte-patcher, not an assembler.

Execution pipeline: parseSections → two CommandLists of `Command{Patch|Restore, address, bytes}` (header :58–65). Enable: applyCommands calls `injector_->patchBytes()` per Patch cmd (:284–290), which snapshots originals into `CodeInjector::patches_` then `TargetProcess::writeMemory` (process_vm_writev, TargetProcess.cpp:184–195). Disable: apply `[DISABLE]` cmds, else restoreCommands(lastEnable_) → `injector_->restore()` (:292–301, :471–487). State kept in the dialog: `enabled_, lastEnable_, lastDisable_, symbols_` (symbols cleared per parse, :153).
→ Extract as `core::AutoAssembler` with `parse(text) -> {enableCmds, disableCmds}` + `apply()/restore()` + symbol table + template generators.

### 3.4 Memory Viewer

- Disassembly: capstone x86-64 (`CS_ARCH_X86/CS_MODE_64`, detail ON) in refreshView :462–528; fallback raw "db xx xx" listing if capstone fails :503–523. Instruction coloring is view-only (:42–49).
- Hex view: buffer read :434–445; per-byte cells + ASCII column :530–553; default page 256 rows × 16 bytes (header :62–63).
- Navigation: jumpTo :365–372, onGo/onPrevPage/onNextPage :374–399, exec-only region snap :404–433, region list refreshRegions :556–581.
- Patching workflow: byte edit onCellDoubleClicked :599–621 writes **without backup**; context-menu patchBytes :744–774 keeps its own private backup map `patchBackups_` (ensurePatchBackup :640–649, restorePatchedBytes :651–661) — disjoint from `CodeInjector::patches_`. NOP-fill action :872–876. Two disjoint undo stores exist today; CLI must standardize on `CodeInjector` (and ideally migrate the viewer onto it too).
- Breakpoints: none anywhere (no int3 machinery); only hardware watchpoints via ce_watch.

Extractables: `core::Disassembler` (capstone wrapper: `disassemble(addr,len) -> instruction list`), page reads, unified patch/restore via CodeInjector.

### 3.5 Pointer Scanner

- `PointerScanner::scan(target, maxOffset, writableOnly)` — PointerScannerDialog.cpp:16–48: chunked 64 KB scan of readable (+writable optional) regions, aligned 8-byte reads, hit when `diff = target − val ∈ [−maxOffset, +maxOffset]`.
- `struct PointerHit { uintptr_t baseAddress; int64_t offset; uintptr_t finalAddress; }` — include/gui/PointerScannerDialog.h:16–20.
- Already Qt-free but physically located in `gui/` → pure move to `src/core`.
- Known limitations (parity notes for CLI docs): single-level pointers only, no dereference verification pass, no dedup/ranking.
- Dialog wiring onStartScan :94–121.

### 3.6 AoB Injection

- Pattern parsing delegated to core: `MemoryScanner::parseAobPattern` (:95–109); scan runs `firstScan` with type=ArrayOfByte/mode=Aob on a background QThread (:111–165, finishScan :167–202).
- Apply semantics: re-read each selected address, re-verify pattern bytes still present, then `injector_->patchBytes(addr, replacement)` (:204–270); restore via `injector_->restore` (:272–299). Verify-then-patch loop is the engine-worthy part.
- Template generation: AutoAssemblerDialog::insertTemplate (AobInjection kind, :587–599) and `MainWindow::makePatchScript` :3371–3398.

### 3.7 Value Monitor

- Monitors one address/type: readCurrent :39–59 (size-by-type read), QTimer @100 ms → poll :61–117 appends old→new rows on change. Logic = poll + change journal. Trivially extracted as a polling service emitting events (CLI prints NDJSON). No pointer support; numeric types + fixed 8-byte read for AOB/String.

### 3.8 Privileges / ptrace quirks (must-know for CLI runtime)

- Everything hinges on ptrace + `/proc/<pid>/mem` + `process_vm_writev`: same-uid (yama scope 0/1 rules) or root. The GUI builds a hint reading `/proc/sys/kernel/yama/ptrace_scope` (ptraceHint, MainWindow.cpp:184–195) — replicate verbatim in CLI error output.
- ce_watch child spawn: fork+execv; child stdout+stderr dup2'd onto a pipe; binary located relative to `/proc/self/exe` (`<build>/ce_watch/ce_watch`) with PATH fallback (resolveCeWatchPath, DebugWatch.cpp:146–170). CLI/daemon reuse directly.
- FD env vars: parent passes command/response fds via `COMFYENGINE_WATCH_CMD_FD` / `COMFYENGINE_WATCH_RESP_FD` (set after fork, DebugWatch.cpp:229–234; consumed in ce_watch/main.cpp:69–76; cmd fd O_NONBLOCK, Watcher.cpp:40–42).
- Hardware watchpoints: DR0 = aligned addr; DR7 = L0 | RW<<16 | LEN<<18 (RW: 01=write, 11=read/write; LEN bit mapping Watcher.cpp:440–447; alignment :431–438); DR6 cleared on trap (:312–330); arms every existing thread and re-arms newly spawned ones (:157–179, :376–385). Exactly **one slot (DR0) per watcher process** → concurrent watches need multiple sessions; supported today via static `gWatcherMap` (DebugWatch.cpp:38–56) and static `writeViaWatcher` (:397–413) routing writes to any live session for that pid.
- Teardown quirk: stop() SIGINTs child, waits ~5 s, SIGKILLs, then — because a killed watcher leaves debug regs armed — runs fallback attach-all-tids-and-zero-DR0/DR6/DR7 sweep (`clearHardwareWatchpointsFallback` DebugWatch.cpp:75–134, :341–369). CLI must keep this path alive (never hard-exit the daemon while sessions run).

---

## 4. Reference: File Formats & Protocols

### 4.1 Cheat-table JSON format (must remain compatible)

Root object, single key `entries` (array). Written onSaveTable MainWindow.cpp:2121–2156; parsed onLoadTable :2158–2221.

Non-script entry:

| Key | Type | Notes |
|---|---|---|
| `address` | string | `"0x%llx"` hex with 0x prefix (:2134); parsed with base auto-detect `toULongLong(&ok, 0)` (:2184) |
| `type` | string | `"Byte" \| "2 Bytes" \| "4 Bytes" \| "8 Bytes" \| "Float" \| "Double" \| "AOB" \| "String"` (:2135 write; :2188–2195 read; unknown → Int32) |
| `description` | string | |
| `pointer` | bool | default false (:2200) |
| `frozen` | bool | default false (:2201) |
| `valueBytes` | string | space-separated lowercase hex bytes of `stored`, e.g. `"1e 00 00 00"` (:2139–2145 write; token parse :2202–2210) |

Script entry keys: `isScript: true`, `description`, `script` (full AA text incl. `[ENABLE]/[DISABLE]`), `active` (written :2128–2132 but **ignored on load** — always restored inactive, :2173–2180).

⚠️ Pointer-entry `offsets` are **not persisted** today. CLI tables should add an `offsets` array (backward compatible: absent = empty) and fix the GUI loader to use it when present.

File filter in GUI: "Cheat Tables (*.json)".

### 4.2 Auto Assembler language

See §3.3 for the exact supported grammar and pipeline. CLI exposes it unchanged; do NOT silently accept CE-only directives — return a clear unsupported-directive error naming the line.

### 4.3 ce_watch wire protocol

Two channels between `DebugWatchSession` (parent) and `ce_watch` child:

1. **Event stream** (child stdout, also stderr merged): lines
   `tid=%d rip=0x%llx dr6=%s bytes=<hex> inst=<mnemonic op>`
   (Watcher.cpp:360–371; parsed by DebugWatchSession::parseLine DebugWatch.cpp:292–339; aggregated per-rip with counts). Without capstone, `inst=` carries raw bytes only (Watcher.cpp:71–76, :338–352).
2. **Command channel** (newline-delimited, over inherited fds):
   `WRITE <hexaddr> <hexbyte>...` → `OK\n` | `ERR ...\n`
   (Watcher.cpp:498–536; responses :563–568; client sendWriteCommand DebugWatch.cpp:371–395.) WRITE uses PTRACE_INTERRUPT + POKEDATA word-loop (:538–561) because `process_vm_writev` may fail while the tracee is stopped; `TargetProcess::writeMemory` falls back automatically (TargetProcess.cpp:188–195).

The CLI does not need to speak this protocol directly — `DebugWatchSession` already wraps it — but agents may want raw event passthrough (NDJSON), so the daemon translates.

---

## 5. Target Architecture

```
┌──────────────┐    unix socket     ┌────────────────────────────┐
│ comfy        │ ─────────────────► │ comfyd                     │
│ (thin client)│   NDJSON requests  │  SessionManager            │
└──────┬───────┘   + event stream   │  ├─ TargetSession (attach) │───► src/core
       │                            │  ├─ ScanSession (results,  │     TargetProcess
       │ stateless cmds:            │  │   shadow copy, undo)    │     MemoryScanner
       │ link src/core directly     │  ├─ CheatTable (freeze     │     CodeInjector
       ▼                            │  │   pump thread)          │     DebugWatchSession
  no daemon needed                  │  └─ WatchSessions (per-pid │     + NEW services:
                                    │      ce_watch wrappers)    │      AutoAssembler
┌──────────────┐                    └────────────────────────────┘      CheatTable
│ comfy exec - │ ◄── batch NDJSON over stdin/stdout (agent tool loops)  ScalarCodec
└──────────────┘                                                        Disassembler
```

Components:

1. **`src/core` additions (Qt-free):**
   - `core/AutoAssembler.{h,cpp}` — parser + executor + symbol table + aobscan/aobscanmodule + templates (from §3.3).
   - `core/CheatTable.{h,cpp}` — WatchEntry vector + freeze pump (`std::thread`, 50 ms tick, cond-var stop) + typed get/set + JSON save/load (format §4.1, plus new `offsets` field).
   - `core/ScalarCodec.{h,cpp}` — parse/format/read/write per `ValueType`; replaces the six duplicated switch blocks.
   - `core::resolvePointerChain(TargetProcess&, base, offsets)` — free function.
   - `core/Analysis.{h,cpp}` — meta-scoring heuristics + snapshot/track-changes diffing + spike detection thresholds (parameterized, defaults = GUI values).
   - `core/Disassembler.{h,cpp}` — capstone x86-64 wrapper; graceful degradation without capstone.
   - Move `PointerScanner`/`PointerHit` files from `gui/` → `core/` (no code change beyond includes).
   - `core/Json.h` — minimal JSON writer/parser for tables & IPC (hand-rolled ~300 lines or vendored single-header nlohmann — decision point P0; format is tiny enough either way, escaping correctness is the only risk).

2. **`comfyd` (daemon, `src/cli/daemon/`):** owns sessions; unix socket (default `$XDG_CACHE_HOME/comfyengine/comfy.sock`, mode 0600); auto-started on demand by client; shuts down on idle timeout / explicit `shutdown`; refuses second instance per socket path. Runs freeze pumps and watch sessions; translates ce_watch event lines → NDJSON notifications.

3. **`comfy` (client, `src/cli/client/`):** arg parsing, `--json`, exit codes; for stateless commands links core directly (no daemon round-trip); for session commands talks to the daemon. Also supports `exec -` batch mode.

4. **GUI refactor:** MainWindow/dialogs consume the same new core services (delete the duplicated switch blocks, hidden-AA-dialog hack, private patch backup map).

---

## 6. CLI Command Specification (draft v1)

Conventions:
- Addresses accept: hex `0x…`, decimal, `symbol+offset`, module names, and pointer-chain syntax `[base]+0x10]+4]`.
- Types: `byte i16 i32 i64 float double aob string` (aliases match table labels).
- Every command: `--json`, `--help`; destructive ones: `--yes`, `--dry-run`.

```
# Discovery
comfy ps [--json]                          # process list
comfy modules                              # module name → base/size
comfy regions [--perm rwx] [--path SUB]    # memory map of target
comfy schema                               # machine-readable self-description (JSON)

# Session
comfy attach <pid|name> [--session NAME]
comfy detach [--session NAME]
comfy status [--sessions]

# Read / write
comfy read <addr-expr> <type>[@len]
comfy write <addr-expr> <type> <value> [--yes|--dry-run]
comfy hexdump <addr> <len>
comfy disasm <addr> [-n COUNT]             # falls back to db-listing sans capstone

# Scan workflow (daemon-backed)
comfy scan first --type T --mode M [--value V] [--value2 V]
               [--align N] [--start A] [--end A] [--writable] [--executable]
               [--hex] [--include-masked]
comfy scan next  [same filters]
comfy scan undo | reset | count
comfy scan list [--limit N] [--offset M] [--with-values]   # slices server-side

# Watchlist / freeze (daemon-backed)
comfy watch add <addr-expr> <type> [desc]
comfy watch rm <index>
comfy watch set <index> <value>
comfy watch freeze <index> on|off
comfy watch list [--with-values]
comfy table save <file> | load <file>

# Patching / injection
comfy patch <addr> <hexbytes> [--yes]      # via CodeInjector (auto-backup)
comfy unpatch <addr>
comfy patches                              # list live patches w/ originals
comfy nop <addr> <len> [--yes]
comfy aob replace <pattern> <hexbytes> [--limit N] [--verify] [--yes]
comfy aa run <file> [--section enable|disable]
comfy aa enable <name> | disable <name>    # saved/table scripts

# Analysis
comfy pscan <target-addr> --max-offset N [--writable-only]
comfy snapshot take | diff                 # track-changes
comfy meta                                 # heuristic ranking of last scan
comfy monitor <addr-expr> <type>           # streams NDJSON change events until ^C

# Debug watchpoints (daemon-backed, ce_watch)
comfy wp start <addr> <write|access> [1|2|4|8] [--name N]
comfy wp hits [--name N] [--json]
comfy wp stop [--name N]

# Batch / automation
comfy exec -                                # NDJSON requests on stdin, responses+events on stdout
```

Example agent session (one-shot style):

```console
$ PID=$(comfy ps --json | jq -r '.[] | select(.name=="testgame") | .pid')
$ comfy attach $PID
$ comfy scan first --type i32 --mode exact --value 100
{"count": 4211, "scanId": 1}
$ comfy scan next --mode decreased --limit 5 --with-values --json
[{"address":"0x55c0a1b2e140","value":87}, ...]
$ comfy write 0x55c0a1b2e140 i32 9999 --yes
$ comfy watch add '[baseNode]+0]+0]+0' i32 "secret via chain"
```

---

## 7. Wire Protocol (daemon)

Newline-delimited JSON over `SOCK_STREAM` unix socket (same-uid only):

```jsonc
// request
{"id": 42, "cmd": "scan.next", "args": {"mode": "decreased", "limit": 20}}
// response
{"id": 42, "ok": true,  "result": {"count": 1337, "returned": 20, "rows": [...]}}
{"id": 43, "ok": false, "error": {"code": "ptrace_denied", "message": "...", "hint": "echo 0 > /proc/sys/kernel/yama/ptrace_scope (or run as root)"}}
// async notification (no id)
{"event": "monitor.change", "session": "default", "data": {"address": "...", "old": 87, "new": 86}}
{"event": "wp.hit", "name": "w1", "data": {"tid": 1234, "rip": "0x...", "inst": "mov [rax], edx"}}
```

Rules: one JSON value per line; responses strictly ordered per connection but notifications interleave; `cancel` request aborts a running scan on that session (maps to `requestCancel`). Long-running foreground commands (`monitor`) stream until client sends `stop`.

---

## 8. Output Contract for Agents

- **Human mode (default):** aligned tables, colors off when not a TTY.
- **`--json`:** UTF-8, one document (or NDJSON for streams). Field names stable forever once shipped; additions allowed, renames/removals require major version.
- **Exit codes:**

| Code | Meaning |
|---|---|
| 0 | success (incl. empty results) |
| 1 | generic failure |
| 2 | usage error (bad args) |
| 3 | not attached |
| 4 | ptrace/permission denied (hint included in JSON error) |
| 5 | target died / vanished |
| 6 | invalid address/value/type |
| 7 | file I/O error (tables, scripts) |
| 8 | cancelled / timed out |
| 9 | operation produced no target (e.g., unpatch unknown addr) |

- **Bounded output:** every listing command takes `--limit/--offset`; scan lists default `--limit 50`; `schema` documents all of this.
- **Self-description:** `comfy schema` returns `{version, commands:[{name, args:{...}, examples, errors:[codes]}], types, modes}` — generated from the same registration table that dispatches commands, so it can't drift.

---

## 9. Phase Breakdown

### Phase 0 — Core extraction refactor *(largest, highest risk)*
Goal: zero behavior change; GUI keeps compiling/working.
1. Add `ScalarCodec`, `resolvePointerChain`, `CheatTable` (data+pump, no JSON yet), `AutoAssembler`, `Analysis`, `Disassembler`; move `PointerScanner` to core.
2. Rewire GUI call sites listed in §3 to the new services; delete duplicated switch blocks; delete hidden-AA-dialog hack (MainWindow.cpp:3017–3050); unify viewer patch backups onto CodeInjector.
3. Decide JSON strategy (hand-rolled vs vendored nlohmann) and implement table serialization in core (keep byte-compatible format; add optional `offsets` field; fix ignored-`active` quirk only behind an opt-in flag).
Acceptance: ctest green; manual GUI smoke (scan→watch→freeze→table save/load→AA enable/disable) identical; no Qt includes under `src/core`.

### Phase 1 — CLI skeleton + stateless commands
1. `CE_BUILD_CLI` CMake option; `src/cli` with shared arg-parse + JSON/error/exit-code plumbing.
2. Ship: `ps`, `attach`(stateless check), `regions`, `modules`, `read`, `write`, `hexdump`, `disasm`, `patch/unpatch/nop`, `status`, `help`, `schema` (subset).
Acceptance: end-to-end against test_watch/testgame from a script using only `--json` + exit codes.

### Phase 2 — Daemon & session model
1. `comfyd` + socket + lifecycle (auto-start, idle shutdown, 0600 perms, single-instance lock).
2. TargetSession, ScanSession (server-side results, slicing, undo stack, cancel), CheatTable session w/ freeze pump, ValueMonitor streaming.
3. Client subcommands: `scan *`, `watch *`, `table *`, `monitor`, `snapshot take|diff`, `meta`.
Acceptance: freeze survives daemon-client disconnect; scan of 100k+ results sliced not serialized whole; Ctrl-C cancels scan cleanly (exit 8).

### Phase 3 — Full feature parity
1. `aa run/enable/disable` via core::AutoAssembler (incl. aobscan/module symbols).
2. `aob replace` verify-then-patch; `pscan`; `meta`; `snapshot diff`.
3. Debug watchpoints: `wp start/hits/stop` wrapping DebugWatchSession; multiple concurrent sessions per pid (DR0-slot rule documented in help text); teardown keeps clear-HW-regs fallback.
Acceptance: every README "What You Get" bullet has a CLI equivalent demonstrated in the e2e suite.

### Phase 4 — Agent ergonomics
1. `comfy exec -` batch NDJSON mode; `comfy schema` full generation from dispatch table.
2. Event subscriptions (`wp.hit`, `monitor.change`, `freeze.violation`).
3. Safety polish: `--dry-run` on all writers, `--yes` gating, confirmation-free scripting mode documented.
Acceptance: an LLM given only `comfy schema --json` completes a scripted find-modify-freeze task unassisted (dogfood test).

### Phase 5 — Testing & docs
1. Extend `testgame` (already ideal: prints live addresses of baseNode/midNode/tailNode/secretValue every 200 ms, main.cpp:145–158; known globals health=100/speed=1.0/stamina=75/ammo=30/grenades=3/money=5000, main.cpp:15–33; 3-hop chain baseNode.next→midNode→tailNode→&secretValue, main.cpp:56–63) and/or switch CI to plain-C `ce_watch/test_target.c` to drop the Qt dependency in tests.
2. e2e suite (bash or Python driving the CLI): launch target → scan → narrow → write → verify → freeze → pointer-chain resolve → AoB replace/restore → AA enable/disable → wp hit capture → table save/load roundtrip.
3. Docs: `comfy(1)` man page, `docs/CLI.md` (human quickstart), `AGENTS.md` snippet users paste into agent configs.

---

## 10. Testing Strategy

- **Unit (ctest):** ScalarCodec round-trips (all types, hex/dec), AA parser golden tests (each directive, comments, sections, error cases), pointer-chain resolution vs testgame fixture addresses, table JSON round-trip incl. legacy files without `offsets`, meta-analysis scoring fixtures, JSON escaping.
- **Integration (needs privileges):** run under same-uid against `test_watch`/testgame; skip gracefully (report reason) when yama blocks ptrace.
- **E2E:** the Phase 5 suite doubles as the release gate; runs both human and `--json` modes and asserts exit codes.
- **Regression guard for GUI:** existing suites + smoke checklist after each Phase-0 rewiring commit.

## 11. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Phase-0 refactor regresses GUI | Mechanical extractions first (verbatim moves), one service per commit, ctest + manual smoke gate |
| Freeze pump thread-safety bugs | CheatTable owns a mutex; pump tick copies entries-under-lock then writes outside; fuzz with rapid add/remove/freeze |
| Daemon dies mid-freeze → values drift | Freeze violation events; watchdog: on daemon start, detect stale session files and warn |
| Killed ce_watch leaves DRs armed | Preserve clearHardwareWatchpointsFallback path; never SIGKILL daemon while wp sessions active (drain first) |
| Huge result sets flood agents/IPC | Server-side slicing only (`--limit/--offset` mandatory-default), count-only responses unless rows requested |
| Socket abuse | 0600 unix socket, same-uid check on connect, optional `--socket-path` for isolation |
| yama/ptrace failures confuse agents | Error code 4 always carries the yama hint string in `error.hint` |
| Format drift between GUI/CLI tables | Single serializer in core used by both frontends; golden-file tests |

## 12. Open Questions

1. Binary names: `comfy` + `comfyd`? (alternatives: `ce-cli`, subcommand `comfyengine cli`)
2. JSON dependency: hand-rolled writer/parser vs vendored nlohmann single-header (P0 decision).
3. Should the daemon eventually expose the same interface over TCP (containerized/remote targets)? Not now — design keeps transport swappable.
4. Future MCP server wrapper around the same dispatch table — trivially additive once Phase 4 lands; out of scope for v1.
5. Fix or preserve quirks: pointer-watch entries with empty offsets (2991–3004), ignored `active` on table load (2173–2180), viewer's unbacked double-click writes (599–621)? Recommendation: preserve defaults, expose fixes behind flags, revisit post-v1.
