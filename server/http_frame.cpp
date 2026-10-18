#include "http_frame.h"
#include <algorithm>
#include <cctype>

namespace http {

std::string Lower(std::string s) {
    for (auto& c : s) c = char(std::tolower((unsigned char)c));
    return s;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string Request::Get(const std::string& name) const {
    std::string n = Lower(name);
    for (auto& [k, v] : headers) if (Lower(k) == n) return v;
    return {};
}

bool ParseRequest(const std::string& raw, Request& out) {
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return false;
    std::string reqline = raw.substr(0, line_end);
    size_t s1 = reqline.find(' ');
    size_t s2 = reqline.find(' ', s1 == std::string::npos ? 0 : s1 + 1);
    if (s1 == std::string::npos || s2 == std::string::npos) return false;
    out.method  = reqline.substr(0, s1);
    out.path    = reqline.substr(s1 + 1, s2 - s1 - 1);
    out.version = Trim(reqline.substr(s2 + 1));

    size_t pos = line_end + 2;
    while (true) {
        size_t e = raw.find("\r\n", pos);
        if (e == std::string::npos || e == pos) break;
        std::string h = raw.substr(pos, e - pos);
        size_t c = h.find(':');
        if (c == std::string::npos) return false;
        out.headers.emplace_back(Trim(h.substr(0, c)), Trim(h.substr(c + 1)));
        pos = e + 2;
    }

    size_t body_start = raw.find("\r\n\r\n");
    if (body_start == std::string::npos) return false;
    body_start += 4;
    size_t clen = 0;
    std::string cl = out.Get("Content-Length");
    if (!cl.empty()) { try { clen = std::stoul(cl); } catch (...) { return false; } }
    if (clen > 32 * 1024 * 1024) return false;
    if (raw.size() < body_start + clen) return false;
    out.body.assign(raw.begin() + body_start, raw.begin() + body_start + clen);
    return true;
}

std::string SerializeResponse(const Response& r) {
    std::string reason = "Unknown";
    switch (r.status) {
        case 200: reason = "OK"; break;
        case 204: reason = "No Content"; break;
        case 400: reason = "Bad Request"; break;
        case 401: reason = "Unauthorized"; break;
        case 404: reason = "Not Found"; break;
        case 500: reason = "Internal Server Error"; break;
        default: break;
    }

    std::string head = "HTTP/1.1 " + std::to_string(r.status) + " " + reason + "\r\n";
    for (auto& [k, v] : r.headers) head += k + ": " + v + "\r\n";
    head += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    head += "Connection: close\r\n\r\n";
    head.append(reinterpret_cast<const char*>(r.body.data()), r.body.size());
    return head;
}

}