# ComfyEngine CLI — `comfy` & `comfyd`

Headless frontends over the same Qt-free engine (`ce_core`) the GUI uses. Built for
scripting and AI agents: every command supports `--json`, stable exit codes, bounded
output, and runtime self-description.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build          # comfy + comfyd land in build/src/cli/
```

Disable with `-DCE_BUILD_CLI=OFF`.

## Two execution modes

| Mode | Needs daemon? | How to address target |
|---|---|---|
| **Direct** | no | append `--pid <pid>` |
| **Session** | yes (`comfyd &`) | `comfy attach <pid\|name>`, then omit `--pid` |

The daemon (`comfyd --socket-path PATH`) owns stateful things: scan result sets,
watchlists with freeze enforcement, hardware watchpoints. Start it manually; stop
with `kill <pid>` or `pkill comfyd`. Socket default:
`$XDG_CACHE_HOME/comfyengine/comfy.sock` (mode 0600).

## Pointer chains

Syntax: `[baseExpr]+off]+off]` — `baseExpr` is any address expression (literal,
`module+offset`, even `0x…+24`). Each `+off]` segment **dereferences the current
pointer, then adds off**. Nesting (`[[..]]`) is invalid. Example walk of
`node->next->next->value_ptr`:

```console
$ comfy read '[0x55c00000+8]+8]+0' i32     # hop: read(0x55c00008) -> +8 -> read -> +0
```

Invalid chains exit 6 and the error message repeats this syntax plus the exact
problem. `comfy walk '[base]+8]+8]+0' ptr` resolves verbosely, printing every
hop — use it to debug chains instead of manual step-by-step reads.

## Sample game (headless demo)

```console
$ setsid env QT_QPA_PLATFORM=offscreen ./build/testgame/ce-mini-game \
    --allow-ptrace </dev/null >/tmp/game.log 2>&1 &
$ setsid comfyd </dev/null >/tmp/comfyd.log 2>&1 &
$ comfy attach ce-mini-game
```

(`setsid env VAR=x cmd &` detaches fully so background jobs never hold your
shell; record `$!` for cleanup.)

The game exposes static globals (health=100 i32, speed=1.0f, stamina=75.0,
ammo=30, grenades=3, money=5000) plus a 3-node pointer chain
(values 111→222→333) whose last `next` targets `secretValue=1337`.
`ce-mini-game --help` lists its flags.

## Quickstart (agent-flavored)

```console
$ PID=$(comfy --json ps | jq -r '.[] | select(.name=="ce-mini-game") | .pid')
$ comfyd &                       # once per boot
$ comfy attach $PID
$ comfy --json scan first --type i32 --mode exact --value 100
{"count": 3210, "phase": "first"}
$ comfy scan next --mode decreased
$ comfy --json scan list --with-values --limit 10
$ comfy watch add 0x55c0a1b2e140 i32 hp
$ comfy watch freeze 0 on        # enforced every 50 ms by the daemon
$ comfy write '[baseNode]+0]+0]+0' i32 9999
```

Direct mode without a daemon:

```console
$ comfy read 0x55c0a1b2e140 i32 --pid 12345
100
$ comfy patch 0x401000 90 90 90 --pid 12345   # recorded; undo via `unpatch`
```

## Command reference

Run `comfy help` for the live list or `comfy schema` for machine-readable output —
that schema is generated from the dispatch table and includes usage lines, value
types, scan modes, address-expression syntax and the exit-code table. Agents should
call it first.

Groups:

- **Process/target**: `ps` `attach` `detach` `status` `regions` `modules`
- **Memory**: `read` `write [--dry-run]` `hexdump` `disasm`
- **Patching**: `patch` `unpatch` `patches` `nop` (all recorded & restorable)
- **Scanning**: `scan first|next|undo|reset|count|list|cancel` (filters: `--type
  byte|i16|i32|i64|float|double|aob|string`, `--mode exact|unknown|changed|
  unchanged|increased|decreased|gt|lt|between|aob`, `--align --writable
  --executable --hex --include-masked`)
- **Watchlist**: `watch add|rm|set|freeze|script|list` (`rm all` clears),
  `table save|load
  [--offsets] [--activate-scripts]`
- **Analysis**: `snapshot take|diff` `meta` — struct-aware ranking: every entry
  reports `inboundPtrs` (how many pointers target it ±64B) and `neighbors`
  (field-texture coherence); real game objects outrank lone stack copies.
  `scan list --sort address` gives deterministic row order. `pscan`
  `monitor` (NDJSON events)
- **Injection**: `aob-replace` (verify-then-patch), `aa-run <file>
  [--section enable|disable]`, `aa-store/aa-enable/aa-disable <name>`
- **Watchpoints**: `wp start|stop|hits|list` (hardware DR0 via ce_watch helper)

Address expressions: hex `0x…`, decimal, `module+offset`, pointer chains
`[base]+0x10]+off]` (final `]` optional). Types accept `@len` for variable-size
reads (`aob@32`, `string@64`) plus `ptr` — a 64-bit pointer read/write whose
value renders as hex (ideal for walking linked structures). Struct signatures:
`scan first --sig "i32=100 float=1.0" --writable` builds the AoB pattern from
typed key=value pairs. Output is JSON automatically when stdout is not a TTY
(`--human` forces tables; `--json` accepted in any position).

## Agent contract

- `--json` → single-line JSON results; errors as
  `{"error":{"code","message","hint","exit"}}`; streams as NDJSON events.
- Exit codes: `0` ok · `1` generic · `2` usage · `3` not attached · `4` ptrace
  denied (hint included) · `5` target gone · `6` invalid address/value · `7` file
  I/O · `8` cancelled · `9` unknown object.
- Listings are paginated server-side (`--limit`/`--offset`, defaults keep output
  small); scan rows stay in the daemon until requested.
- Batch mode: `comfy exec -` reads NDJSON requests (`{"id":1,"cmd":"read",
  "args":["0x…","i32"]}`) or plain shell-ish lines on stdin and echoes one JSON
  response line each — one long-lived process for whole tool loops.
- No confirmation gates: writes execute immediately (use `--dry-run` to preview).
  Patches are always recorded for `unpatch`.

## Permissions

Memory access uses `process_vm_readv/writev` (+ptrace fallbacks). Under yama
`ptrace_scope=1` you can only attach to your own descendants; otherwise run as root
or set scope 0. Errors carry this hint automatically. Hardware watchpoints spawn the
`ce_watch` helper (located relative to the binary) and clean up debug registers even
after SIGKILL.

## Tests

```bash
ctest --test-dir build --output-on-failure
```

Runs engine unit tests plus `tests/cli_e2e.sh`, an end-to-end suite that spawns a
real target process and drives attach/scan/freeze/table/AA/watchpoint flows through
the actual binaries (skips gracefully where ptrace is unavailable).
