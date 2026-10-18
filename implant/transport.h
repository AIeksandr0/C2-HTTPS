#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace transport {

struct Endpoint {
    std::string host;
    std::string ip;
    std::string path;
    int         port = 443;
};

struct Result {
    bool ok = false;
    int  status = 0;
    std::vector<uint8_t> body;
};

Result Post(const Endpoint& ep,
            const std::vector<uint8_t>& body,
            const std::string& session_id,
            int op,
            const std::vector<std::pair<std::string, std::string>>& extra_headers);
}