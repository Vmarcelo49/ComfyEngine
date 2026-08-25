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
pass() { echo "PASS $1"; }
rd() { $CE --json read "$@" | jq -r '.value'; }
failf() { echo "FAIL $1"; FAIL=1; }

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
$CE attach ce-mini-game --socket "$SOCK"

echo "== locate Player.health via AoB signature (health=100 || speed=1.0f)"
$CE --json scan first --sig "i32=100 float=1.0" --writable --socket "$SOCK" > "$WORK/aob.json"
$CE --json scan list --limit 500 --socket "$SOCK" > "$WORK/rows.json"
echo "aob rows: $(jq '.rows | length' "$WORK/rows.json")"
HEALTH=""
for A in $(jq -r '.rows[].address' "$WORK/rows.json"); do A=${A#0x};
    MO=$(rd "0x$A+24" i32 --pid $GPID)
    if [ "$MO" = "5000" ]; then HEALTH="$A"; break; fi
done
echo "Player.health @ 0x$HEALTH"
[ -n "$HEALTH" ] && check health-initial "100" "$(rd "0x$HEALTH" i32 --pid $GPID)" || { echo "FAIL player-locate"; FAIL=1; }

echo "== write + freeze"
$CE write "0x$HEALTH" i32 9999 --pid $GPID >/dev/null
check health-written "9999" "$(rd "0x$HEALTH" i32 --pid $GPID)"
$CE watch add "0x$HEALTH" i32 hp --socket "$SOCK" >/dev/null
$CE watch freeze 0 on --socket "$SOCK" >/dev/null
$CE write "0x$HEALTH" i32 5 --pid $GPID >/dev/null
sleep 0.3
check frozen         "9999" "$(rd "0x$HEALTH" i32 --pid $GPID)"
$CE watch freeze 0 off --socket "$SOCK" >/dev/null
$CE watch rm 0 --socket "$SOCK" >/dev/null

echo "== walk baseNode(111) -> midNode(222) -> tailNode(333) -> secretValue"
find_node() { # $1=value $2=expected-next-addr(hex, empty for last) -> prints node addr
    $CE --json scan reset --socket "$SOCK" >/dev/null
    $CE --json scan first --type i32 --mode exact --value "$1" --writable --socket "$SOCK" >/dev/null
    for N in $($CE --json scan list --limit 500 --sort address --socket "$SOCK" | jq -r '.rows[].address'); do
        N=${N#0x}
        if [ -z "$2" ]; then
            echo "$N"; return 0
        fi
        NXT=$(rd "0x$N+8" ptr --pid $GPID 2>/dev/null)
        [ -z "$NXT" ] && continue
        case "$NXT" in 0x*) ;; *) continue;; esac
        NXDEC=$(( 0x${NXT#0x} ))
        DEC2=$(( 0x$2 ))
        if [ "$NXDEC" -eq "$DEC2" ]; then echo "$N"; return 0; fi
    done
    return 1
}
TAIL=$(find_node 333 "")
[ -n "$TAIL" ] || { echo "FAIL tail-not-found"; FAIL=1; }
MID=$(find_node 222 "$TAIL")
BASE=$(find_node 111 "$MID")
echo "base=0x$BASE mid=0x$MID tail=0x$TAIL"
[ -n "$BASE" ] && [ -n "$MID" ] && [ -n "$TAIL" ] && pass nodes-found || failf nodes-found
BP8=$(printf '0x%x' $(( 0x$BASE + 8 )))
check chain-3hop   "1337" "$(rd "[${BP8}]+8]+8]+0" i32 --pid $GPID)"
SECP=$(printf '0x%x' $(( 0x$TAIL + 8 )))
check chain-secret "1337" "$(rd "[${SECP}]+0" i32 --pid $GPID)"

echo "== struct-aware meta: rescan health=100 writable, Player should be crowned"
$CE --json scan reset --socket "$SOCK" >/dev/null
$CE write "0x$HEALTH" i32 100 --pid $GPID >/dev/null
$CE --json scan first --type i32 --mode exact --value 100 --writable --socket "$SOCK" >/dev/null
META=$($CE --json meta --limit 200 --socket "$SOCK")
echo "$META" | jq -c '.top[0]'
echo "$META" | jq -c --arg x "0x$HEALTH" '.top[] | select(.address==$x)'
echo "$META" | jq -r --arg x "0x$HEALTH" '[.top[].address] | index($x) != null' | grep -q true \
    && pass meta-crowns-player || failf meta-crowns-player
INB=$(echo "$META" | jq -r --arg x "0x$HEALTH" '.top[] | select(.address==$x) | .inboundPtrs')
[ "${INB:-0}" -ge 1 ] && echo "PASS meta-inbound ($INB refs)" || failf meta-inbound
$CE detach --socket "$SOCK" >/dev/null
kill $DPID 2>/dev/null
kill -9 $GPID 2>/dev/null
echo "== done FAIL=$FAIL"
echo EXITING
exit $FAIL
