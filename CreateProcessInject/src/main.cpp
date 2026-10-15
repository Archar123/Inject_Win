#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <filesystem>
#include <string>
#include <algorithm>
#include <cctype>

#include "injector.h"
#include "util.h"
#include "IniFile.h"

namespace fs = std::filesystem;

struct Config
{
    std::string mode;           // "Create" or "Scan"
    std::string targetProcess;  // e.g. "notepad.exe"
    std::string exePath;        // full path for Create mode
    std::string commandLine;    // optional
    std::string workingDir;     // optional
    std::string dllPath;        // DLL to inject (absolute or relative)
    bool        manualMap;      // use ManualMap instead of LoadLibrary
    bool        waitForClose;   // Create: wait for existing instance to exit first
    DWORD       scanIntervalMs; // Scan: polling interval
    DWORD       postInjectDelayMs; // Create: delay before ResumeThread
    bool        resumeAfterInject;  // Create: whether to ResumeThread after inject
    bool        suspendBeforeInject; // Scan: freeze all threads via NtSuspendProcess during inject
};

static void PrintBanner()
{
    std::cout << "============================================\n"
                 "  CreateProcessInject - config driven\n"
                 "  Modes: Create | Scan\n"
                 "============================================\n";
}

static bool LoadConfig(const fs::path& iniPath, Config& cfg)
{
    IniFile ini;
    if (!ini.LoadFromFile(iniPath.string()))
    {
        std::cout << "Failed to open cfg.ini at: " << iniPath.string() << "\n";
        return false;
    }

    cfg.mode              = ini.GetString("Inject", "Mode", "Create");
    cfg.targetProcess     = ini.GetString("Inject", "TargetProcess", "");
    cfg.exePath           = ini.GetString("Inject", "ExePath", "");
    cfg.commandLine       = ini.GetString("Inject", "CommandLine", "");
    cfg.workingDir        = ini.GetString("Inject", "WorkingDir", "");
    cfg.dllPath           = ini.GetString("Inject", "DllPath", "CLibrary.dll");
    cfg.manualMap         = ini.GetBool("Inject", "ManualMap", false);
    cfg.waitForClose      = ini.GetBool("Inject", "WaitForClose", true);
    cfg.scanIntervalMs    = (DWORD)ini.GetInt("Inject", "ScanIntervalMs", 500);
    cfg.postInjectDelayMs = (DWORD)ini.GetInt("Inject", "PostInjectDelayMs", 2000);
    cfg.resumeAfterInject = ini.GetBool("Inject", "ResumeAfterInject", true);
    cfg.suspendBeforeInject = ini.GetBool("Inject", "SuspendBeforeInject", true);

    if (cfg.targetProcess.empty())
    {
        std::cout << "[cfg] TargetProcess is required.\n";
        return false;
    }

    std::string m;
    m.reserve(cfg.mode.size());
    for (char c : cfg.mode) m.push_back((char)std::tolower((unsigned char)c));
    cfg.mode = m;

    if (cfg.mode != "create" && cfg.mode != "scan")
    {
        std::cout << "[cfg] Mode must be either 'Create' or 'Scan'. Got: " << cfg.mode << "\n";
        return false;
    }

    if (cfg.mode == "create" && cfg.exePath.empty())
    {
        std::cout << "[cfg] Create mode requires ExePath.\n";
        return false;
    }

    return true;
}

static fs::path ResolveDllPath(const Config& cfg, const fs::path& baseDir)
{
    fs::path p(cfg.dllPath);
    if (p.is_absolute())
        return p;
    return baseDir / p;
}

static bool RunCreateMode(const Config& cfg, const fs::path& dllFull)
{
    if (cfg.waitForClose)
        WaitForCloseProcess(cfg.targetProcess);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::string cmdline = cfg.commandLine;
    LPSTR lpCmd = cmdline.empty() ? nullptr : cmdline.data();

    LPCSTR workDir = cfg.workingDir.empty() ? nullptr : cfg.workingDir.c_str();

    std::cout << "[Create] Launching: " << cfg.exePath << "\n";
    if (!CreateProcessA(cfg.exePath.c_str(), lpCmd,
                        nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED,
                        nullptr, workDir, &si, &pi))
    {
        std::cout << "[Create] CreateProcess failed: " << GetLastErrorAsString() << "\n";
        return false;
    }

    std::cout << "[Create] PID=" << pi.dwProcessId
              << " (suspended). Injecting " << dllFull.string() << "\n";

    bool ok = InjectDLL(pi.hProcess, dllFull.string(), cfg.manualMap);
    if (!ok)
    {
        std::cout << "[Create] Injection failed. Terminating target.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    if (cfg.postInjectDelayMs)
        Sleep(cfg.postInjectDelayMs);

    if (cfg.resumeAfterInject)
    {
        std::cout << "[Create] Resuming main thread.\n";
        ResumeThread(pi.hThread);
    }
    else
    {
        std::cout << "[Create] ResumeAfterInject=false. Target left suspended.\n";
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static bool RunScanMode(const Config& cfg, const fs::path& dllFull)
{
    std::cout << "[Scan] Watching for '" << cfg.targetProcess
              << "' (every " << cfg.scanIntervalMs << " ms). Ctrl+C to stop.\n";

    DWORD lastInjectedPid = 0;
    for (;;)
    {
        DWORD pid = FindProcessId(cfg.targetProcess);
        if (pid != 0 && pid != lastInjectedPid)
        {
            HANDLE hProc = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                PROCESS_SUSPEND_RESUME,
                FALSE, pid);
            if (hProc)
            {
                std::cout << "[Scan] Target found PID=" << pid
                          << ". Injecting " << dllFull.string() << "\n";

                bool suspended = false;
                if (cfg.suspendBeforeInject)
                {
                    suspended = SuspendProcess(hProc);
                    std::cout << "[Scan] SuspendProcess: "
                              << (suspended ? "ok" : "failed (continuing anyway)") << "\n";
                }

                bool ok = InjectDLL(hProc, dllFull.string(), cfg.manualMap);

                if (suspended)
                {
                    if (ResumeProcess(hProc))
                        std::cout << "[Scan] Target resumed.\n";
                    else
                        std::cout << "[Scan] ResumeProcess failed: " << GetLastErrorAsString() << "\n";
                }

                CloseHandle(hProc);
                if (ok)
                {
                    std::cout << "[Scan] Injection succeeded for PID " << pid << "\n";
                    lastInjectedPid = pid;
                }
                else
                {
                    std::cout << "[Scan] Injection failed, will retry.\n";
                }
            }
            else
            {
                std::cout << "[Scan] OpenProcess(" << pid << ") failed: "
                          << GetLastErrorAsString() << "\n";
            }
        }
        else if (pid == 0)
        {
            lastInjectedPid = 0;
        }

        Sleep(cfg.scanIntervalMs);
    }
}

int main(int argc, char* argv[])
{
    PrintBanner();

    fs::path exeDir = fs::path(argv[0]).parent_path();
    if (exeDir.empty()) exeDir = fs::current_path();
    fs::current_path(exeDir);

    fs::path iniPath = exeDir / "cfg.ini";
    if (argc >= 2) iniPath = argv[1];

    Config cfg;
    if (!LoadConfig(iniPath, cfg))
        return 1;

    fs::path dllFull = ResolveDllPath(cfg, exeDir);
    if (!fs::exists(dllFull))
    {
        std::cout << "[cfg] DLL not found: " << dllFull.string() << "\n";
        return 2;
    }

    std::cout << "Mode           : " << cfg.mode << "\n"
              << "TargetProcess  : " << cfg.targetProcess << "\n"
              << "DLL            : " << dllFull.string() << "\n"
              << "ManualMap      : " << (cfg.manualMap ? "true" : "false") << "\n";

    if (cfg.mode == "create")
        return RunCreateMode(cfg, dllFull) ? 0 : 10;
    else
        return RunScanMode(cfg, dllFull) ? 0 : 20;
}
