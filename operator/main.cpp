#include "commands.h"

#include <cstdio>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    opcli::RegisterCommands();
    std::printf("c2 operator — 'help' para comandos, 'quit' para sair\n");
    std::string line;
    while (true) {
        std::printf("c2> ");
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) break;
        if (!opcli::Dispatch(line)) break;
    }
    return 0;
}
