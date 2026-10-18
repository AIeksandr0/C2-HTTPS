#include "op_listener.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <vector>

namespace server {

bool OpListener::Start(int port) {
    sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) return false;
    int one = 1;
    ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(uint16_t(port));
    if (::bind(sock_, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
    return ::listen(sock_, 16) == 0;
}

void OpListener::Accept(const Handler& handler) {
    while (true) {
        int fd = ::accept(sock_, nullptr, nullptr);
        if (fd < 0) continue;
        std::thread([fd, handler]() {
            std::string buf;
            char tmp[8192];
            ssize_t n;
            while ((n = ::recv(fd, tmp, sizeof(tmp), 0)) > 0) {
                buf.append(tmp, size_t(n));
                size_t hdr = buf.find("\r\n\r\n");
                if (hdr != std::string::npos) {
                    size_t cl = 0;
                    std::string l = buf.substr(0, hdr);
                    size_t p = l.find("Content-Length:");
                    if (p != std::string::npos) { try { cl = std::stoul(l.substr(p + 15)); } catch (...) {} }
                    if (buf.size() >= hdr + 4 + cl) break;
                }
            }
            http::Request req;
            if (!buf.empty() && http::ParseRequest(buf, req)) {
                http::Response res;
                handler(req, res);
                std::string wire = http::SerializeResponse(res);
                size_t sent = 0;
                while (sent < wire.size()) {
                    ssize_t m = ::send(fd, wire.data() + sent, wire.size() - sent, 0);
                    if (m <= 0) break;
                    sent += size_t(m);
                }
            }
            ::close(fd);
        }).detach();
    }
}

}