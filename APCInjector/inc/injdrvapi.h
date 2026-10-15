#pragma once

//
// Shared control protocol for injdrv.sys.
// Kernel code includes ntddk.h/ntifs.h before this header.
// User mode includes windows.h / winioctl.h before this header.
//

#ifndef CTL_CODE
#error Include ntddk.h or winioctl.h before injdrvapi.h
#endif

#define INJDRV_DEVICE_TYPE 0x8002

#define INJDRV_NT_DEVICE_NAME      L"\\Device\\injdrv"
#define INJDRV_DOS_DEVICE_NAME     L"\\DosDevices\\injdrv"
#define INJDRV_WIN32_DEVICE_NAME   L"\\\\.\\injdrv"

#define INJDRV_MAX_DLLS 8
#define INJDRV_MAX_PATH 520

//
// Full path of one DLL. Length is the byte count of Path, not including the
// terminating NUL. Only paths under \Windows\System32 or \Windows\SysWOW64
// are accepted. The driver keeps the file name and loads it with
// LOAD_LIBRARY_SEARCH_SYSTEM32.
//
typedef struct _INJDRV_DLL_PATH {
	USHORT Length;
	WCHAR Path[INJDRV_MAX_PATH];
} INJDRV_DLL_PATH, *PINJDRV_DLL_PATH;

typedef struct _INJDRV_SET_DLLS_INPUT {
	ULONG Count;
	INJDRV_DLL_PATH Dlls[INJDRV_MAX_DLLS];
} INJDRV_SET_DLLS_INPUT, *PINJDRV_SET_DLLS_INPUT;

//
// Replace the DLL list. Input is INJDRV_SET_DLLS_INPUT.
// System32 entries are queued into native processes.
// SysWOW64 entries are queued into WOW64 processes.
//
#define IOCTL_INJDRV_SET_DLLS \
	CTL_CODE(INJDRV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)

//
// Start queueing APCs for processes that map kernel32.dll after this call.
//
#define IOCTL_INJDRV_ENABLE \
	CTL_CODE(INJDRV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

//
// Stop queueing new APCs. In-flight user-mode routines are left alone.
//
#define IOCTL_INJDRV_DISABLE \
	CTL_CODE(INJDRV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
