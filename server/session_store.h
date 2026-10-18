#pragma once
#include <string>
#include <vector>
#include "session_router.h"

namespace server {

class SessionStore {
public:
    enum class KeyPolicy { SkipKeys, StoreKeys };

    explicit SessionStore(std::string path, KeyPolicy policy = KeyPolicy::SkipKeys);

    bool Save(const std::vector<Session>& sessions);
    std::vector<Session> Load();
    void AppendEvent(const Session& s, const std::string& event);

private:
    std::string path_;
    KeyPolicy   policy_;
};

}