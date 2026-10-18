#include "proto.h"

namespace proto {

static void PutU16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
}
static void PutU32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i)));
}
static uint16_t GetU16(const uint8_t* p) {
    return uint16_t(p[0]) | uint16_t(p[1]) << 8;
}
static uint32_t GetU32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

std::vector<uint8_t> Encode(const Message& m) {
    std::vector<uint8_t> v;
    v.reserve(16 + m.header.session_id.size() + m.payload.size());
    PutU16(v, m.header.version);
    v.push_back(m.header.op);
    v.push_back(m.header.status);
    PutU32(v, m.header.task_id);
    v.push_back(uint8_t(m.header.session_id.size()));
    v.insert(v.end(), m.header.session_id.begin(), m.header.session_id.end());
    v.insert(v.end(), m.payload.begin(), m.payload.end());
    return v;
}

bool Decode(const uint8_t* data, size_t len, Message& out) {
    if (len < 9) return false;
    out.header.version = GetU16(data);
    if (out.header.version != kVersion) return false;
    out.header.op      = data[2];
    out.header.status  = data[3];
    out.header.task_id = GetU32(data + 4);
    const uint8_t sid_len = data[8];
    if (len < size_t(9 + sid_len)) return false;
    out.header.session_id.assign(reinterpret_cast<const char*>(data + 9), sid_len);
    const size_t payload_off = 9 + sid_len;
    out.payload.assign(data + payload_off, data + len);
    return true;
}

}