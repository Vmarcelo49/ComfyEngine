#!/usr/bin/env bash
# Demo: drive ce-mini-game entirely through the comfy CLI (headless, offscreen Qt).
# Usage: game-demo.sh   (expects build tree present)
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CE=$REPO/build/src/cli/comfy
CD=$REPO/build/src/cli/comfyd
GAME=$REPO/build/testgame/ce-mini-game
SOCK=/tmp/opencode/game-demo.sock
WORK=/tmp/opencode/game-demo
rm -rf "$WORK"; mkdir -p "$WORK"
FAIL=0
GPID=""; DPID=""
check() { [ "$2" = "$3" ] && echo "PASS $1" || { echo "FAIL $1: want[$2] got[$3]"; FAIL=1; }; }

pkill -f 'mini-game --allow-ptrace' 2>/dev/null
pkill -f 'cli/comfyd' 2>/dev/null
sleep 0.3
command -v jq >/dev/null || { echo "jq required"; exit 77; }
[ -x "$CE" ] && [ -x "$CD" ] && [ -x "$GAME" ] || { echo "build first"; exit 77; }
pkill -f 'mini-game --allow-ptrace' 2>/dev/null
pkill -f 'cli/comfyd' 2>/dev/null
sleep 0.3
QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-offscreen} "$GAME" --allow-ptrace > "$WORK/game.log" 2>&1 < /dev/null &
GPID=$!
disown
sleep 1.2
"$CD" --socket-path "$SOCK" > "$WORK/d.log" 2>&1 < /dev/null &
DPID=$!
disown
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

echo "== attach by name"
$CE attach ce-mini --socket "$SOCK"

echo "== locate Player.health via AoB signature (health=100 || speed=1.0f)"
$CE --json scan first --type aob --mode aob --value "64 00 00 00 00 00 80 3f" --socket "$SOCK" > "$WORK/aob.json"
$CE --json scan list --limit 500 --socket "$SOCK" > "$WORK/rows.json"
echo "aob rows: $(jq '.rows | length' "$WORK/rows.json")"
HEALTH=""
for A in $(jq -r '.rows[].address' "$WORK/rows.json"); do A=${A#0x};
    MO=$($CE read "0x$A+24" i32 --pid $GPID)
    if [ "$MO" = "5000" ]; then HEALTH="$A"; break; fi
done
echo "Player.health @ 0x$HEALTH"
[ -n "$HEALTH" ] && check health-initial "100" "$($CE read "0x$HEALTH" i32 --pid $GPID)" || { echo "FAIL player-locate"; FAIL=1; }

echo "== write + freeze"
$CE write "0x$HEALTH" i32 9999 --pid $GPID >/dev/null
check health-written "9999" "$($CE read "0x$HEALTH" i32 --pid $GPID)"
$CE watch add "0x$HEALTH" i32 hp --socket "$SOCK" >/dev/null
$CE watch freeze 0 on --socket "$SOCK" >/dev/null
$CE write "0x$HEALTH" i32 5 --pid $GPID >/dev/null
sleep 0.3
check frozen         "9999" "$($CE read "0x$HEALTH" i32 --pid $GPID)"
$CE watch freeze 0 off --socket "$SOCK" >/dev/null
$CE watch rm 0 --socket "$SOCK" >/dev/null

echo "== pointer chain: secret(1337) -> pscan back to tail -> base"
$CE --json scan reset --socket "$SOCK" >/dev/null
$CE --json scan first --type i32 --mode exact --value 1337 --socket "$SOCK" >/dev/null
SECRET=$($CE --json scan list --limit 20000 --socket "$SOCK" \
          | jq -r '.rows[].address' \
          | while read -r S; do
                OWN=$($CE regions --perm w --pid $GPID >/dev/null 2>&1 && echo ok)
                echo "$S"
            done | head -50)
TAIL=""
for S in $SECRET; do S=${S#0x};
    LINK=$($CE --json pscan "0x$S" --max-offset 8 --writable-only --pid $GPID 2>/dev/null | jq -r '.hits[0].base // empty' | head -1)
    [ -z "$LINK" ] && continue
    T=$(printf '%x' $(( 0x${LINK#0x} - 8 )))
    TV=$($CE read "0x$T" i32 --pid $GPID 2>/dev/null)
    if [ "$TV" = "333" ]; then TAIL="$T"; break; fi
done
echo "tailNode @ 0x$TAIL"
check secret-via-chain "1337" "$($CE read "[0x$TAIL+8]+0" i32 --pid $GPID)"

MIDLINK=$($CE --json pscan "0x$TAIL" --max-offset 8 --writable-only --pid $GPID 2>/dev/null | jq -r '.hits[0].base // empty' | head -1)
MID=$(printf '%x' $(( 0x${MIDLINK#0x} - 8 )))
BASELINK=$($CE --json pscan "0x$MID" --max-offset 8 --writable-only --pid $GPID 2>/dev/null | jq -r '.hits[0].base // empty' | head -1)
BASE=$(printf '%x' $(( 0x${BASELINK#0x} - 8 )))
echo "midNode @ 0x$MID   baseNode @ 0x$BASE"
BP8=$(printf '0x%x' $(( 0x$BASE + 8 )))
check chain-3hop "1337" "$($CE read "[${BP8}]+8]+8]+0" i32 --pid $GPID)"

echo "== meta ranking on last scan"
$CE --json meta --limit 3 --socket "$SOCK" | jq -c '.top[0]'
$CE detach --socket "$SOCK" >/dev/null
kill $DPID 2>/dev/null
kill -9 $GPID 2>/dev/null
echo "== done FAIL=$FAIL"
echo EXITING
exit $FAIL
