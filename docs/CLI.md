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

## Quickstart (agent-flavored)

```console
$ PID=$(comfy --json ps | jq -r '.[] | select(.name=="testgame") | .pid')
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
- **Watchlist**: `watch add|rm|set|freeze|script|list`, `table save|load
  [--offsets] [--activate-scripts]`
- **Analysis**: `snapshot take|diff` `meta` `pscan` `monitor` (NDJSON events)
- **Injection**: `aob-replace` (verify-then-patch), `aa-run <file>
  [--section enable|disable]`, `aa-store/aa-enable/aa-disable <name>`
- **Watchpoints**: `wp start|stop|hits|list` (hardware DR0 via ce_watch helper)

Address expressions: hex `0x…`, decimal, `module+offset`, pointer chains
`[base]+0x10]+off]` (final `]` optional). Types accept `@len` for variable-size
reads (`aob@32`, `string@64`).

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
