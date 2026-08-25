#!/usr/bin/env bash
# ComfyEngine CLI end-to-end suite. Skips (code 77) when ptrace access is unavailable.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CE="$REPO/build/src/cli/comfy"
CD="$REPO/build/src/cli/comfyd"
CHILD="$REPO/build/tests/test_target_child"
WORK="$(mktemp -d)"
SOCK="$WORK/comfy.sock"
fail=0
TPID=""; TPID2=""; DPID=""

cleanup() {
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
    [ -n "$TPID" ] && kill -9 "$TPID" 2>/dev/null
    [ -n "$TPID2" ] && kill -9 "$TPID2" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

check() { [ "$2" = "$3" ] && echo "PASS $1" || { echo "FAIL $1: want[$2] got[$3]"; fail=1; }; }
rd() { $CE --json read "$@" | jq -r '.value'; }
pass() { echo "PASS $1"; }
failf() { echo "FAIL $1"; fail=1; }

[ -x "$CE" ] && [ -x "$CD" ] && [ -x "$CHILD" ] || { echo "binaries missing"; exit 77; }

"$CHILD" > "$WORK/t.log" 2>&1 < /dev/null &
TPID=$!
for i in $(seq 1 50); do [ -s "$WORK/t.log" ] && break; sleep 0.1; done
X=$(grep -oP 'X=\K[0-9a-f]+' "$WORK/t.log"); P=$(grep -oP 'P=\K[0-9a-f]+' "$WORK/t.log")
if ! kill -0 "$TPID" 2>/dev/null || [ -z "$X" ]; then echo "cannot start target"; exit 77; fi

echo "--- schema/help"
$CE --json schema | jq -e '.commands | length >= 20' >/dev/null && pass schema || failf schema
$CE --json ps | jq -e 'length >= 1' >/dev/null && pass ps || failf ps

echo "--- stateless (--pid)"
check read          "1337"   "$(rd "0x$X" i32 --pid $TPID)"
$CE --json read "0x$X" i32 --pid $TPID | jq -e '.value == "1337" and .raw == 1337' >/dev/null && pass read-json || failf read-json
$CE write "0x$X" i32 4242 --pid $TPID >/dev/null
check write         "4242"   "$(rd "0x$X" i32 --pid $TPID)"
check ptrchain      "4242"   "$(rd "[0x$P]+0x0" i32 --pid $TPID)"
check ptr-type-hex  "0x0000000000001092" "$(rd "[0x$P]+0x0" ptr --pid $TPID)"
check badaddr       "6"      "$($CE --json read 0xDEADBEEF0000 i32 --pid $TPID >/dev/null 2>&1; echo $?)"
$CE --json hexdump "0x$X" 16 --pid $TPID | jq -e '.length == 16' >/dev/null && pass hexdump || failf hexdump
$CE --json disasm "0x$X" --bytes 16 --count 4 --pid $TPID | jq -e '.disassembled' >/dev/null && pass disasm || failf disasm
MOD=$($CE modules --json --pid $TPID | jq -r '.[0].base'); [ -n "$MOD" ] && pass modules || failf modules
$CE patch "0x$X" 90 --pid $TPID >/dev/null
check patch         "-112"   "$(rd "0x$X" byte --pid $TPID)"
$CE unpatch "0x$X" --pid $TPID >/dev/null
check unpatch       "-110"   "$(rd "0x$X" byte --pid $TPID)"

echo "--- daemon sessions"
"$CD" --socket-path "$SOCK" > "$WORK/d.log" 2>&1 < /dev/null &
DPID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon failed to start"; exit 77; }

$CE attach $TPID --socket "$SOCK" >/dev/null
check status        "$TPID"  "$($CE --json status --socket "$SOCK" | jq -r '.[0].pid')"
$CE write "0x$X" i32 1337 --pid $TPID >/dev/null
CNT=$($CE --json scan first --type i32 --mode exact --value 1337 --socket "$SOCK" | jq -r '.count')
[ "${CNT:-0}" -ge 1 ] && pass scan-first || failf scan-first
HIT=$($CE --json scan list --limit 20000 --socket "$SOCK" | jq -r --arg x "0x$X" '.rows[] | select(.address==$x) | .address')
check scan-list     "0x$X"   "$HIT"
$CE write "0x$X" i32 777 --pid $TPID >/dev/null
$CE scan next --mode exact --value 777 --socket "$SOCK" >/dev/null
HIT2=$($CE --json scan list --socket "$SOCK" | jq -r '.rows[] | select(.address=="0x'"$X"'") | .address')
check scan-narrow   "0x$X"   "$HIT2"

$CE watch add "0x$X" i32 hp --socket "$SOCK" >/dev/null
check watch-val     "777"    "$($CE --json watch list --with-values --socket "$SOCK" | jq -r '.[0].value')"
$CE watch freeze 0 on --socket "$SOCK" >/dev/null
$CE write "0x$X" i32 1 --pid $TPID >/dev/null
sleep 0.3
check frozen        "777"    "$(rd "0x$X" i32 --pid $TPID)"
$CE watch freeze 0 off --socket "$SOCK" >/dev/null
sleep 0.2
$CE table save "$WORK/table.json" --offsets --socket "$SOCK" >/dev/null && pass table-save || failf table-save
$CE watch rm 0 --socket "$SOCK" >/dev/null
$CE table load "$WORK/table.json" --socket "$SOCK" >/dev/null
check table-reload  "1"      "$($CE --json watch list --socket "$SOCK" | jq 'length')"

echo "--- snapshot/meta/aob"
$CE snapshot take --socket "$SOCK"
$CE write "0x$X" i32 555 --pid $TPID >/dev/null
$CE scan next --mode exact --value 555 --socket "$SOCK" >/dev/null
DIF=$($CE --json snapshot diff --socket "$SOCK" | jq -r --arg x "0x$X" '.rows[] | select(.address==$x) | .address')
check snapshot-diff "0x$X"   "$DIF"
METACNT=$($CE --json meta --limit 3 --socket "$SOCK" | jq -r '.top | length')
[ "${METACNT:-0}" -ge 1 ] && pass meta || failf meta
$CE write "0x$X" i32 555 --pid $TPID >/dev/null
AOB=$($CE --json aob-replace "2b 02 00 00" "39 05 00 00" --limit 500 --pid $TPID | jq -r '.count')
[ "${AOB:-0}" -ge 1 ] && pass aob-replace || failf aob-replace
check aob-value     "1337"   "$(rd "0x$X" i32 --pid $TPID)"

echo "--- aa scripts"
printf '[ENABLE]\npatch 0x%s 90\n\n[DISABLE]\nrestore 0x%s\n' "$X" "$X" > "$WORK/nop.aas"
$CE aa-store mynop "$WORK/nop.aas" --socket "$SOCK" >/dev/null
$CE aa-enable mynop --socket "$SOCK" >/dev/null
check aa-enable     "-112"   "$(rd "0x$X" byte --pid $TPID)"
$CE aa-disable mynop --socket "$SOCK" >/dev/null
check aa-disable    "57"     "$(rd "0x$X" byte --pid $TPID)"

echo "--- monitor events"
$CE --json monitor "0x$X" i32 --interval 40 --socket "$SOCK" > "$WORK/m.log" 2>&1 < /dev/null &
MPID=$!
sleep 0.6
$CE write "0x$X" i32 900 --pid $TPID >/dev/null
sleep 0.8
kill $MPID 2>/dev/null
grep -q 'monitor.change' "$WORK/m.log" && pass monitor || failf monitor

echo "--- exec batch"
OUT=$($CE exec - --socket "$SOCK" <<EOF
{"id":1,"cmd":"status","args":[]}
{"id":2,"cmd":"read","args":["0x$X","i32"]}
EOF
)
echo "$OUT" | jq -e 'select(.id==1) | .ok' >/dev/null && pass exec-status || failf exec-status
echo "$OUT" | jq -e 'select(.id==2) | ((.result.lines[0] // "") == "900" or .result.doc.value == "900")' >/dev/null && pass exec-read || failf exec-read

echo "--- watchpoints (needs target that writes its own memory)"
"$CHILD" mutate > "$WORK/t2.log" 2>&1 < /dev/null &
TPID2=$!
for i in $(seq 1 50); do [ -s "$WORK/t2.log" ] && break; sleep 0.1; done
X2=$(grep -oP 'X=\K[0-9a-f]+' "$WORK/t2.log")
if kill -0 "$TPID2" 2>/dev/null && [ -n "$X2" ]; then
    $CE attach $TPID2 --session mut --socket "$SOCK" >/dev/null
    WPERR=$($CE --json wp start "0x$X2" write 4 --name w1 --session mut --socket "$SOCK" 2>&1)
    sleep 1
    RIPS=$($CE --json wp hits --name w1 --session mut --socket "$SOCK" 2>/dev/null | jq -r '[.[0].hits[]] | length' 2>/dev/null)
    if echo "$WPERR" | grep -q '"running":true'; then
        [ "${RIPS:-0}" -ge 1 ] && pass wp-hits || { echo "note: watchpoint armed but no traps (yama?)"; failf wp-hits; }
    else
        echo "note: wp start unsupported here: $WPERR"; failf wp-hits
    fi
    $CE wp stop --session mut --socket "$SOCK" >/dev/null 2>&1
else
    echo "note: mutate target unavailable"; failf wp-hits
fi

echo "== done fail=$fail"
exit $fail
