#include "util.h"

#include <TlHelp32.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

typedef LONG (NTAPI* NtSuspendResumeProcess_t)(HANDLE);

static NtSuspendResumeProcess_t LoadNtApi(const char* name)
{
    static HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return nullptr;
    return reinterpret_cast<NtSuspendResumeProcess_t>(GetProcAddress(hNtdll, name));
}

static std::string ToLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

DWORD FindProcessId(const std::string& processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 process{};
    process.dwSize = sizeof(process);

    std::string wanted = ToLower(processName);
    if (Process32First(snapshot, &process))
    {
        do
        {
            if (ToLower(process.szExeFile) == wanted)
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return pid;
}

void WaitForCloseProcess(const std::string& processName)
{
    DWORD pid = FindProcessId(processName);
    if (pid == 0)
        return;

    std::cout << "Found '" << processName << "' process. Waiting for it to close..." << std::endl;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD exitCode = 0;
    while (hProc && (GetExitCodeProcess(hProc, &exitCode), exitCode == STILL_ACTIVE))
    {
        Sleep(1000);
    }

    if (hProc != NULL)
        CloseHandle(hProc);
}

std::string GetLastErrorAsString()
{
    DWORD err = GetLastError();
    if (err == 0)
        return "";

    LPSTR buf = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf, 0, nullptr);
    std::string msg;
    if (n && buf)
    {
        msg.assign(buf, n);
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n'))
            msg.pop_back();
    }
    if (buf) LocalFree(buf);
    std::ostringstream oss;
    oss << msg << " (0x" << std::hex << err << ")";
    return oss.str();
}

bool SuspendProcess(HANDLE hProc)
{
    static auto pNtSuspendProcess = LoadNtApi("NtSuspendProcess");
    if (!pNtSuspendProcess) return false;
    return pNtSuspendProcess(hProc) >= 0;
}

bool ResumeProcess(HANDLE hProc)
{
    static auto pNtResumeProcess = LoadNtApi("NtResumeProcess");
    if (!pNtResumeProcess) return false;
    return pNtResumeProcess(hProc) >= 0;
}
