#include "session_store.h"
#include "shared/crypto.h"

#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace server {

SessionStore::SessionStore(std::string path, KeyPolicy policy)
    : path_(std::move(path)), policy_(policy) {}

static std::string JsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            default: o.push_back(c);
        }
    }
    return o;
}

bool SessionStore::Save(const std::vector<Session>& sessions) {
    std::ofstream f(path_, std::ios::trunc);
    if (!f) return false;
    for (const auto& s : sessions) {
        f << "{"
          << "\"id\":\"" << JsonEscape(s.session_id) << "\","
          << "\"host\":\"" << JsonEscape(s.hostname) << "\","
          << "\"user\":\"" << JsonEscape(s.username) << "\","
          << "\"os\":\"" << JsonEscape(s.os) << "\","
          << "\"alive\":" << (s.alive ? "true" : "false");
        if (policy_ == KeyPolicy::StoreKeys) {
            f << ",\"key\":\"" << crypto::ToHex(s.key) << "\"";
            f << ",\"client_pub\":\"" << crypto::ToHex(s.client_pub) << "\"";
        }
        f << "}\n";
    }
    ::chmod(path_.c_str(), S_IRUSR | S_IWUSR);
    return true;
}

std::vector<Session> SessionStore::Load() {
    std::vector<Session> out;
    std::ifstream f(path_);
    if (!f) return out;
    std::string line;
    auto extract = [](const std::string& src, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t p = src.find(pat);
        if (p == std::string::npos) return {};
        p += pat.size();
        size_t e = src.find('"', p);
        return e == std::string::npos ? std::string{} : src.substr(p, e - p);
    };
    while (std::getline(f, line)) {
        Session s;
        s.session_id = extract(line, "id");
        s.hostname   = extract(line, "host");
        s.username   = extract(line, "user");
        s.os         = extract(line, "os");
        s.alive      = line.find("\"alive\":true") != std::string::npos;
        std::string k = extract(line, "key");
        if (!k.empty()) s.key = crypto::FromHex(k);
        if (!s.session_id.empty()) out.push_back(std::move(s));
    }
    return out;
}

void SessionStore::AppendEvent(const Session& s, const std::string& event) {
    std::ofstream f(path_ + ".events", std::ios::app);
    if (!f) return;
    f << "{\"id\":\"" << JsonEscape(s.session_id) << "\",\"event\":\"" << JsonEscape(event) << "\"}\n";
}

}