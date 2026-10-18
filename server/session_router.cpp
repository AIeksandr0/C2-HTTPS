#include "session_router.h"

namespace server {

Session* SessionRouter::Create(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& server_pub,
                               const std::vector<uint8_t>& client_pub,
                               const std::string& sid) {
    std::lock_guard<std::mutex> lk(mu_);
    Session& s = sessions_[sid];
    s.session_id = sid;
    s.key        = key;
    s.server_pub = server_pub;
    s.client_pub = client_pub;
    s.first_seen = Clock::now();
    s.last_seen  = s.first_seen;
    s.alive      = true;
    return &s;
}

Session* SessionRouter::Touch(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) return nullptr;
    it->second.last_seen = Clock::now();
    return &it->second;
}

Session* SessionRouter::Get(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(sid);
    return it == sessions_.end() ? nullptr : &it->second;
}

std::vector<Session> SessionRouter::List() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<Session> out;
    out.reserve(sessions_.size());
    for (auto& [_, s] : sessions_) out.push_back(s);
    return out;
}

void SessionRouter::MarkDead(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(sid);
    if (it != sessions_.end()) it->second.alive = false;
}

size_t SessionRouter::Sweep(Clock::duration timeout) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = Clock::now();
    size_t removed = 0;
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (now - it->second.last_seen > timeout) { it = sessions_.erase(it); ++removed; }
        else ++it;
    }
    return removed;
}

uint32_t SessionRouter::AllocTaskId(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) return 0;
    return it->second.next_task_id++;
}

}