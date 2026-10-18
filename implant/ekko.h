#pragma once
#include <cstdint>

namespace ekko {
void SleepObfuscated(uint32_t ms, uint32_t jitter = 0);
bool Init();
}