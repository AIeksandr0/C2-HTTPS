#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace http {

struct Request {
    std::string method, path, version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
    std::string Get(const std::string& name) const;
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

bool ParseRequest(const std::string& raw, Request& out);

std::string SerializeResponse(const Response& r);

std::string Trim(const std::string& s);
std::string Lower(std::string s);

}