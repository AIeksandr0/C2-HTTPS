#include "transport.h"
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include <cstring>

namespace transport {

static std::wstring Wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), &w[0], n);
    return w;
}

Result Post(const Endpoint& ep,
            const std::vector<uint8_t>& body,
            const std::string& session_id,
            int op,
            const std::vector<std::pair<std::string, std::string>>& extra_headers) {
    Result res;

    HINTERNET session = WinHttpOpen(L"WinHTTP/5.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return res;

    std::wstring wip = Wide(ep.ip);
    HINTERNET conn = WinHttpConnect(session, wip.c_str(), (INTERNET_PORT)ep.port, 0);
    if (!conn) { WinHttpCloseHandle(session); return res; }

    std::wstring wpath = Wide(ep.path);
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath.c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return res; }

    DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    std::wstring headers = L"Content-Type: application/octet-stream\r\n";
    headers += L"Host: " + Wide(ep.host) + L"\r\n";
    headers += L"X-Op: " + std::to_wstring(op) + L"\r\n";
    if (!session_id.empty()) headers += L"X-Session-Id: " + Wide(session_id) + L"\r\n";
    for (auto& [k, v] : extra_headers) headers += Wide(k) + L": " + Wide(v) + L"\r\n";

    BOOL sent = WinHttpSendRequest(req, headers.c_str(), (DWORD)-1L,
                                   (LPVOID)body.data(), (DWORD)body.size(),
                                   (DWORD)body.size(), 0);
    if (!sent || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return res;
    }

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    res.status = int(status);

    DWORD avail = 0;
    do {
        if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
        std::vector<uint8_t> chunk(avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, chunk.data(), avail, &read) || read == 0) break;
        res.body.insert(res.body.end(), chunk.begin(), chunk.begin() + read);
    } while (avail > 0);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    res.ok = (res.status == 200);
    return res;
}

}