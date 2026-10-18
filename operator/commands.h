#pragma once
#include <map>
#include <string>
#include <vector>

namespace opcli {
void RegisterCommands();
bool Dispatch(const std::string& line);
}