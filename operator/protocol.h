#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace opcli {

struct SessionInfo {
    std::string id, host, user, os;
    bool alive = true;
};

class C2Client {
public:
    explicit C2Client(std::string base);

    bool Sessions(std::vector<SessionInfo>& out);
    bool Task(const std::string& sid, int op, const std::vector<uint8_t>& payload);
    bool Ping();

private:
    bool Post(const std::string& path, const std::string& body, std::string& resp);
    std::string base_;
};
}