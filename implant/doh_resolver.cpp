#include "doh_resolver.h"
#include "config.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <cstring>
#include <random>

namespace doh {

static bool HttpPost(const std::wstring& url,
                     const std::vector<uint8_t>& body,
                     std::vector<uint8_t>& out) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0}, path[1024] = {0};
    uc.lpszHostName = host;   uc.dwHostNameLength = 256;
    uc.lpszUrlPath  = path;   uc.dwUrlPathLength  = 1024;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;

    HINTERNET session = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;

    bool secure = uc.nScheme == INTERNET_SCHEME_HTTPS;
    HINTERNET conn = WinHttpConnect(session, host, uc.nPort, 0);
    if (!conn) { WinHttpCloseHandle(session); return false; }

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", path, nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return false; }

    LPCWSTR hdrs = L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n";
    bool ok = WinHttpSendRequest(req, hdrs, (DWORD)-1L,
                                 (LPVOID)body.data(), (DWORD)body.size(),
                                 (DWORD)body.size(), 0) &&
              WinHttpReceiveResponse(req, nullptr);

    if (ok) {
        DWORD avail = 0;
        do {
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
            std::vector<uint8_t> chunk(avail);
            DWORD read = 0;
            if (!WinHttpReadData(req, chunk.data(), avail, &read) || read == 0) break;
            out.insert(out.end(), chunk.begin(), chunk.begin() + read);
        } while (avail > 0);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok && !out.empty();
}

static std::vector<uint8_t> BuildQuery(const std::string& name) {
    std::vector<uint8_t> q;
    q.push_back(0x12); q.push_back(0x34);
    q.push_back(0x01); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x01);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);

    size_t i = 0;
    while (i < name.size()) {
        size_t dot = name.find('.', i);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - i;
        if (len == 0 || len > 63) return {};
        q.push_back(uint8_t(len));
        q.insert(q.end(), name.begin() + i, name.begin() + dot);
        i = dot + 1;
    }
    q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x01);
    q.push_back(0x00); q.push_back(0x01);
    return q;
}

static std::vector<std::string> ParseAnswer(const std::vector<uint8_t>& r) {
    std::vector<std::string> ips;
    if (r.size() < 12) return ips;
    uint16_t qd = (r[4] << 8) | r[5];
    uint16_t an = (r[6] << 8) | r[7];

    size_t p = 12;
    for (int i = 0; i < qd; ++i) {
        while (p < r.size() && r[p] != 0) {
            if ((r[p] & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + r[p];
        }
        if (p < r.size() && r[p] == 0) p += 1;
        p += 4;
    }

    for (int i = 0; i < an && p + 10 <= r.size(); ++i) {
        if ((r[p] & 0xC0) == 0xC0) p += 2;
        else { while (p < r.size() && r[p] != 0) p += 1 + r[p]; p += 1; }
        if (p + 10 > r.size()) break;
        uint16_t type = (r[p] << 8) | r[p + 1];
        uint16_t rdlen = (r[p + 8] << 8) | r[p + 9];
        p += 10;
        if (p + rdlen > r.size()) break;
        if (type == 1 && rdlen == 4) {
            char buf[16];
            wsprintfA(buf, "%u.%u.%u.%u", r[p], r[p + 1], r[p + 2], r[p + 3]);
            ips.push_back(buf);
        }
        p += rdlen;
    }
    return ips;
}

static std::vector<std::string> SystemResolve(const std::string& host) {
    std::vector<std::string> out;
    addrinfoW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::wstring w(host.begin(), host.end());
    addrinfoW* res = nullptr;
    if (GetAddrInfoW(w.c_str(), nullptr, &hints, &res) != 0) return out;
    for (addrinfoW* p = res; p; p = p->ai_next) {
        char buf[INET_ADDRSTRLEN] = {0};
        sockaddr_in* sa = (sockaddr_in*)p->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        if (buf[0]) out.emplace_back(buf);
    }
    FreeAddrInfoW(res);
    return out;
}

std::vector<std::string> Resolve(const std::string& hostname) {
    static const char* urls[] = { cfg::kDohV4, cfg::kDohAlt, cfg::kDohV6 };
    auto query = BuildQuery(hostname);

    for (const char* tmpl : urls) {
        char url[512];
        snprintf(url, sizeof(url), tmpl, hostname.c_str());
        std::wstring wurl(url, url + strlen(url));

        std::vector<uint8_t> resp;
        if (!HttpPost(wurl, query, resp)) continue;
        auto ips = ParseAnswer(resp);
        if (!ips.empty()) return ips;
    }

    return SystemResolve(hostname);
}

std::string PickOne(const std::vector<std::string>& ips) {
    if (ips.empty()) return {};
    std::mt19937 rng(GetTickCount());
    std::uniform_int_distribution<size_t> d(0, ips.size() - 1);
    return ips[d(rng)];
}

}