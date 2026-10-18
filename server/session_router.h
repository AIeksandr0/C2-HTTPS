#pragma once
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace server {

using Clock = std::chrono::steady_clock;

struct Session {
    std::string session_id;
    std::string hostname, username, os;
    std::vector<uint8_t> key;
    std::vector<uint8_t> server_pub;
    std::vector<uint8_t> client_pub;
    Clock::time_point    last_seen{};
    Clock::time_point    first_seen{};
    uint32_t             next_task_id = 1;
    bool                 alive = true;
    int                  pid = 0;
    std::string          arch, integrity;
    uint32_t             ip = 0;
};

class SessionRouter {
public:
    Session* Create(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& server_pub,
                    const std::vector<uint8_t>& client_pub,
                    const std::string& sid);
    Session* Touch(const std::string& sid);
    Session* Get(const std::string& sid);
    std::vector<Session> List();
    void MarkDead(const std::string& sid);
    size_t Sweep(Clock::duration timeout);
    uint32_t AllocTaskId(const std::string& sid);

private:
    std::mutex mu_;
    std::map<std::string, Session> sessions_;
};

}