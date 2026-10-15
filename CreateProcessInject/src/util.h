#pragma once
#include <string>
#include <Windows.h>

DWORD FindProcessId(const std::string& processName);
void  WaitForCloseProcess(const std::string& processName);
std::string GetLastErrorAsString();

// NtSuspendProcess / NtResumeProcess wrappers. Freeze/thaw every thread of the
// target in one shot so a running game can't race the injector during Scan mode.
bool SuspendProcess(HANDLE hProc);
bool ResumeProcess(HANDLE hProc);
