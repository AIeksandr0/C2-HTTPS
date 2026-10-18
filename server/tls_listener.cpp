#include "tls_listener.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <thread>

namespace server {

struct TlsListener::Impl {
    TlsConfig cfg;
    SSL_CTX*  ctx = nullptr;
    int       sock = -1;
};

static bool RecvRequest(SSL* ssl, http::Request& out) {
    std::string buf;
    char tmp[8192];
    size_t expected_total = 0;
    while (true) {
        int n = SSL_read(ssl, tmp, sizeof(tmp));
        if (n <= 0) return false;
        buf.append(tmp, size_t(n));

        size_t hdr_end = buf.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            if (expected_total == 0) {
                size_t cl = 0;
                std::string head = buf.substr(0, hdr_end);
                std::string lhead = http::Lower(head);
                size_t p = lhead.find("content-length:");
                if (p != std::string::npos) {
                    size_t e = buf.find("\r\n", p);
                    std::string v = buf.substr(p + 15, e == std::string::npos ? std::string::npos : e - (p + 15));
                    try { cl = std::stoul(http::Trim(v)); } catch (...) { return false; }
                }
                expected_total = hdr_end + 4 + cl;
            }
            if (buf.size() >= expected_total) break;
        }
        if (buf.size() > 64 * 1024 * 1024) return false;
    }
    return http::ParseRequest(buf, out);
}

TlsListener::TlsListener(TlsConfig cfg) : impl_(new Impl{std::move(cfg)}) {}

TlsListener::~TlsListener() {
    if (impl_->sock >= 0) ::close(impl_->sock);
    if (impl_->ctx) SSL_CTX_free(impl_->ctx);
    delete impl_;
}

bool TlsListener::Start() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    impl_->ctx = SSL_CTX_new(TLS_server_method());
    if (!impl_->ctx) return false;

    SSL_CTX_set_min_proto_version(impl_->ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(impl_->ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");

    if (SSL_CTX_use_certificate_chain_file(impl_->ctx, impl_->cfg.cert_file.c_str()) != 1) return false;
    if (SSL_CTX_use_PrivateKey_file(impl_->ctx, impl_->cfg.key_file.c_str(), SSL_FILETYPE_PEM) != 1) return false;
    if (!SSL_CTX_check_private_key(impl_->ctx)) return false;

    impl_->sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->sock < 0) return false;
    int one = 1;
    ::setsockopt(impl_->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(uint16_t(impl_->cfg.port));

    if (::bind(impl_->sock, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
    return ::listen(impl_->sock, 128) == 0;
}

void TlsListener::Accept(const Handler& handler) {
    while (true) {
        int fd = ::accept(impl_->sock, nullptr, nullptr);
        if (fd < 0) continue;

        std::thread([this, fd, handler]() {
            SSL* ssl = SSL_new(impl_->ctx);
            if (!ssl) { ::close(fd); return; }
            SSL_set_fd(ssl, fd);

            if (SSL_accept(ssl) <= 0) {
                SSL_free(ssl);
                ::close(fd);
                return;
            }

            http::Request req;
            if (RecvRequest(ssl, req)) {
                http::Response res;
                try {
                    handler(req, res);
                } catch (const std::exception& e) {
                    res.status = 500;
                    res.body.assign(e.what(), e.what() + std::strlen(e.what()));
                }
                std::string wire = http::SerializeResponse(res);
                size_t sent = 0;
                while (sent < wire.size()) {
                    int n = SSL_write(ssl, wire.data() + sent, int(wire.size() - sent));
                    if (n <= 0) break;
                    sent += size_t(n);
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            ::close(fd);
        }).detach();
    }
}

}