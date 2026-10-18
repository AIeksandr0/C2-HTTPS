#pragma once
#include <functional>
#include "http_frame.h"

namespace server {

class OpListener {
public:
    using Handler = std::function<void(http::Request&, http::Response&)>;
    bool Start(int port = 8443);
    void Accept(const Handler& handler);
private:
    int sock_ = -1;
};

}