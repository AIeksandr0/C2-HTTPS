#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"; BIN="$ROOT/build_linux"; OUT="$ROOT/out"; STATE="$OUT/probe_state.bin"
mkdir -p "$OUT"
rm -f "$ROOT/sessions.jsonl" "$ROOT/sessions.jsonl.events" "$STATE" "$OUT"/*.log

pkill -f 'build_linux/c2server' 2>/dev/null
for _ in $(seq 1 20); do pgrep -f 'build_linux/c2server' >/dev/null || break; sleep 0.2; done

stdbuf -oL -eL "$BIN/c2server" "$ROOT/certs/server.crt" "$ROOT/certs/server.key" 8444 \
    >"$OUT/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT

PIN=""
for _ in $(seq 1 80); do
    PIN=$(grep -oE 'x25519 pub: [0-9a-f]+' "$OUT/server.log" 2>/dev/null | head -1 | awk '{print $3}')
    grep -q 'listening on' "$OUT/server.log" 2>/dev/null && break
    sleep 0.25
done
[ -z "$PIN" ] && { echo "[FAIL] no pin"; cat "$OUT/server.log"; exit 1; }
grep -q 'listening on' "$OUT/server.log" || { echo "[FAIL] server did not open the port"; cat "$OUT/server.log"; exit 1; }
echo "[ok] pin=$PIN"
export C2_SERVER_PUB="$PIN"

echo; echo "=== 1. Hello + Beacon (no task) ==="
"$OUT/probe_hello" hello 8444 "$STATE" | tee "$OUT/probe_hello.log"
"$OUT/probe_hello" beacon 8444 "$STATE" | tee "$OUT/probe_beacon0.log"
SID=$(grep -oE 'SID=[0-9a-f]+' "$OUT/probe_hello.log" | cut -d= -f2)
[ -z "$SID" ] && { echo "[FAIL] no sid"; kill $SRV; exit 1; }
echo "[ok] sid=$SID"

echo; echo "=== 2. operator: sessions ==="
printf 'sessions\nquit\n' | "$BIN/c2operator" 2>&1 | grep -v '^c2> $'

echo; echo "=== 3. operator: enqueue Shell ==="
printf 'use %s\nshell echo hello-c2\nquit\n' "$SID" | "$BIN/c2operator" 2>&1 | grep -E '\[\+\]|\[\*\]'

echo; echo "=== 4. pending on server ==="
curl -s http://127.0.0.1:8443/op/sessions; echo

echo; echo "=== 5. beacon receives Shell and sends Result ==="
"$OUT/probe_hello" beacon 8444 "$STATE" | tee "$OUT/probe_beacon1.log"

echo; echo "=== 6. results on server ==="
curl -s -X POST http://127.0.0.1:8443/op/results -d "{\"sid\":\"$SID\"}" | tee "$OUT/results.json"; echo
echo "--- decoded ---"
python3 - "$OUT/results.json" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as e:
    print("no results:", e); raise SystemExit
if not data:
    print("(empty)")
for r in data:
    raw = bytes.fromhex(r["data"])
    # Shell returns 4-byte exit code (little endian) + stdout/stderr
    code = int.from_bytes(raw[:4], "little") if len(raw) >= 4 else -1
    print(f"task={r['task_id']} op={r['op']} exit={code} stdout={raw[4:]!r}")
PY

echo; echo "=== 7. sessions.jsonl ==="
cat "$ROOT/sessions.jsonl" 2>/dev/null || echo "(empty)"
echo; echo "=== server.log ==="
cat "$OUT/server.log"
echo; echo "=== done ==="