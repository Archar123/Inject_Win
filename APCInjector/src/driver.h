#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "injdrvapi.h"

#define INJ_POOL_TAG 'jnID'
#define INJ_NAME_CHARS 128

#define INJ_LOAD_IGNORE_CODE_AUTHZ_LEVEL 0x00000010UL
#define INJ_LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800UL

typedef PVOID (NTAPI* PFN_PS_GET_PROCESS_WOW64_PROCESS)(_In_ PEPROCESS Process);
typedef NTSTATUS (NTAPI* PFN_PS_WRAP_APC_WOW64_THREAD)(_Inout_ PVOID* ApcContext, _Inout_ PVOID* ApcRoutine);
typedef BOOLEAN (NTAPI* PFN_PS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);

typedef struct _INJ_PROCESS {
	LIST_ENTRY Link;
	HANDLE ProcessId;
	BOOLEAN Wow64;
	BOOLEAN Injected;
	PVOID Kernel32Base;
	SIZE_T Kernel32Size;
	PVOID KernelBaseBase;
	SIZE_T KernelBaseSize;
} INJ_PROCESS, *PINJ_PROCESS;

typedef struct _INJ_GLOBALS {
	FAST_MUTEX Lock;
	BOOLEAN Enabled;
	PDEVICE_OBJECT DeviceObject;
	LIST_ENTRY Processes;
	ULONG NativeCount;
	ULONG Wow64Count;
	WCHAR NativeDlls[INJDRV_MAX_DLLS][INJ_NAME_CHARS];
	WCHAR Wow64Dlls[INJDRV_MAX_DLLS][INJ_NAME_CHARS];
	PFN_PS_GET_PROCESS_WOW64_PROCESS GetWow64Process;
	PFN_PS_WRAP_APC_WOW64_THREAD WrapApcWow64Thread;
	PFN_PS_IS_PROTECTED_PROCESS IsProtectedProcess;
	PFN_PS_IS_PROTECTED_PROCESS IsProtectedProcessLight;
} INJ_GLOBALS;

extern INJ_GLOBALS g_Inj;

void InjDbg(_In_z_ _Printf_format_string_ PCSTR Format, ...);

NTSTATUS InjInitialize(void);
void InjShutdown(void);
NTSTATUS InjSetDllList(_In_reads_bytes_(InputLength) const VOID* Input, _In_ ULONG InputLength);
void InjSetEnabled(_In_ BOOLEAN Enabled);

void InjOnLoadImage(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo);
void InjOnProcessExit(_In_ HANDLE ProcessId);

NTSTATUS InjCreateDevice(_In_ PDRIVER_OBJECT DriverObject);
void InjDeleteDevice(void);
