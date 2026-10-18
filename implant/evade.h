#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace evade {
bool LooksLikeSandbox();
void* ResolveNtdll(const char* func);
std::string Decode(const std::vector<uint8_t>& enc);
std::vector<uint8_t> EncodeRuntime(const std::string& plain);
}