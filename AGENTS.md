# AGENTS.md — driving ComfyEngine headlessly

ComfyEngine ships an agent-first CLI. If you are an LLM agent asked to inspect,
scan, patch, or freeze memory of a process, use `comfy`/`comfyd` — do not reimplement
ptrace logic.

## Bootstrap (30 seconds)

```bash
comfy schema          # machine-readable description of EVERY command, type, mode and exit code
comfy help            # human index
comfy help <command>  # per-command usage + examples
```

Full human docs: `docs/CLI.md`. Everything below is the cheat sheet.

## Rules of thumb

1. **Two modes.** Quick one-shots need no daemon: append `--pid <pid>` to
   direct commands (`read write hexdump disasm patch unpatch nop patches pscan
   aob-replace aa-run regions modules ps`). Anything stateful — scans,
   watchlists/freeze, tables, monitors, watchpoints — needs `comfyd &` first,
   then `comfy attach <pid|name>`.
2. **Always pass `--json`** when scripting; outputs are single-line JSON with
   stable keys. Errors arrive as `{"error":{code,message,hint,exit}}` on stdout
   with a non-zero exit code (see `comfy schema` → exitCodes).
3. **Scans live server-side.** `scan first|next` return only counts;
   fetch rows with `scan list --limit N [--with-values]`. Cancel with
   `scan cancel`. Undo with `scan undo`.
4. **Narrowing strategy that works:** exact-scan the known value → have the game
   change it → `scan next --mode changed|exact --value V`. Prefer adding
   `--writable` early: most game state lives in rw pages.
5. **Finding structs fast:** AoB signature scan beats brute narrowing, e.g.
   `scan first --type aob --mode aob --value "64 00 00 00 00 00 80 3f"`
   (int32 100 followed by float 1.0). Verify neighbors with typed reads at
   offsets (`read 0xADDR+24 i32`).
6. **Pointer chains:** syntax `[baseExpr]+off]+off]`; every segment dereferences
   then adds off; no nesting. To follow a `next` pointer stored at node+8 start
   with `[nodeAddr+8]+0`. Invalid chains exit 6 with the syntax in the message —
   debug hop-by-hop with plain reads.
7. **Who points here?** `pscan <addr> --max-offset N [--writable-only]`
   returns inbound pointers `{base, offset, final}` — perfect for backtracking
   linked structures or finding stable paths to a dynamic address.
8. **Freeze = watchlist entry.** `watch add <addr> <type> [desc]`,
   `watch freeze <index> on`, enforcement runs at 50 ms inside comfyd and
   survives client disconnects. Prove it: corrupt externally, re-read.
9. **Persist work:** `table save f.json --offsets` / `table load f.json`.
   Auto Assembler scripts: `aa-store name file` → `aa-enable name` /
   `aa-disable name` (undo-safe via recorded originals).
10. **Writes are immediate** (no confirmation gates) — rehearse with
    `--dry-run` when unsure. Patches are always recorded for `unpatch`.

## Sample target

`build/testgame/ce-mini-game` (run with `--allow-ptrace`; `--help` explains).
Headless: prefix `QT_QPA_PLATFORM=offscreen`. Known state: health=100 i32,
speed=1.0f, stamina=75.0, ammo=30, grenades=3, money=5000, plus nodes
111→222→333 whose chain ends at secretValue=1337.

## Cleanup

Kill the game by PID; stop the daemon with `kill <comfyd-pid>`
(it shuts down gracefully). List sessions any time via `comfy status`.
