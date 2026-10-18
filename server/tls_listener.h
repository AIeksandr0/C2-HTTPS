#pragma once
#include <functional>
#include <string>
#include "http_frame.h"

namespace server {

struct TlsConfig {
    std::string cert_file;
    std::string key_file;
    int         port = 443;
    int         threads = 0;
};

class TlsListener {
public:
    using Handler = std::function<void(http::Request&, http::Response&)>;

    explicit TlsListener(TlsConfig cfg);
    ~TlsListener();

    bool Start();
    void Accept(const Handler& handler);

private:
    struct Impl;
    Impl* impl_;
};

}