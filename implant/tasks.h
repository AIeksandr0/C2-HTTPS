#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tasks {

struct Inbound {
    uint8_t  op = 0;
    uint32_t task_id = 0;
    std::vector<uint8_t> payload;
};

bool Execute(const Inbound& task, std::vector<uint8_t>& result);
extern uint32_t sleep_ms;
extern uint32_t jitter_pct;
}