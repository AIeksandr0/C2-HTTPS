#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace doh {

std::vector<std::string> Resolve(const std::string& hostname);

std::string PickOne(const std::vector<std::string>& ips);

}