#include "inject.h"
#include "exports.h"
#include "apc.h"

static PVOID InjAllocate(_In_ SIZE_T Size)
{
	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, Size, INJ_POOL_TAG);
	if (buffer != NULL)
	{
		RtlZeroMemory(buffer, Size);
	}
	return buffer;
}

static void InjFree(_In_opt_ PVOID Buffer)
{
	if (Buffer != NULL)
	{
		ExFreePoolWithTag(Buffer, INJ_POOL_TAG);
	}
}

static BOOLEAN InjEndsWithI(_In_ PCUNICODE_STRING Value, _In_ PCWSTR Suffix)
{
	UNICODE_STRING suffix;
	USHORT chars;
	USHORT index;
	USHORT start;

	RtlInitUnicodeString(&suffix, Suffix);
	if (Value->Buffer == NULL || Value->Length < suffix.Length)
	{
		return FALSE;
	}

	chars = suffix.Length / sizeof(WCHAR);
	start = (Value->Length - suffix.Length) / sizeof(WCHAR);
	for (index = 0; index < chars; index++)
	{
		if (RtlUpcaseUnicodeChar(Value->Buffer[start + index]) !=
			RtlUpcaseUnicodeChar(suffix.Buffer[index]))
		{
			return FALSE;
		}
	}

	return TRUE;
}

static BOOLEAN InjIsSystemProcess(_In_ HANDLE ProcessId)
{
	HANDLE systemPid = PsGetProcessId(PsInitialSystemProcess);
	return ProcessId == NULL || ProcessId == systemPid;
}

static BOOLEAN InjIsCurrentProcessProtected(void)
{
	PEPROCESS process = PsGetCurrentProcess();

	if (g_Inj.IsProtectedProcess != NULL && g_Inj.IsProtectedProcess(process))
	{
		return TRUE;
	}

	if (g_Inj.IsProtectedProcessLight != NULL && g_Inj.IsProtectedProcessLight(process))
	{
		return TRUE;
	}

	return FALSE;
}

static BOOLEAN InjIsCurrentProcessWow64(void)
{
#if defined(_WIN64)
	if (g_Inj.GetWow64Process == NULL)
	{
		return FALSE;
	}

	return g_Inj.GetWow64Process(PsGetCurrentProcess()) != NULL;
#else
	return FALSE;
#endif
}

typedef enum _INJ_IMAGE_KIND {
	InjImageOther = 0,
	InjImageKernel32,
	InjImageKernelBase
} INJ_IMAGE_KIND;

static INJ_IMAGE_KIND InjClassifyImage(_In_ PCUNICODE_STRING Name, _In_ BOOLEAN Wow64)
{
	if (Wow64)
	{
		if (InjEndsWithI(Name, L"\\Windows\\SysWOW64\\kernel32.dll") ||
			InjEndsWithI(Name, L"\\SystemRoot\\SysWOW64\\kernel32.dll"))
		{
			return InjImageKernel32;
		}
		if (InjEndsWithI(Name, L"\\Windows\\SysWOW64\\kernelbase.dll") ||
			InjEndsWithI(Name, L"\\SystemRoot\\SysWOW64\\kernelbase.dll"))
		{
			return InjImageKernelBase;
		}
	}
	else
	{
		if (InjEndsWithI(Name, L"\\Windows\\System32\\kernel32.dll") ||
			InjEndsWithI(Name, L"\\SystemRoot\\System32\\kernel32.dll"))
		{
			return InjImageKernel32;
		}
		if (InjEndsWithI(Name, L"\\Windows\\System32\\kernelbase.dll") ||
			InjEndsWithI(Name, L"\\SystemRoot\\System32\\kernelbase.dll"))
		{
			return InjImageKernelBase;
		}
	}

	return InjImageOther;
}

static PINJ_PROCESS InjFindProcessLocked(_In_ HANDLE ProcessId)
{
	PLIST_ENTRY entry;

	for (entry = g_Inj.Processes.Flink; entry != &g_Inj.Processes; entry = entry->Flink)
	{
		PINJ_PROCESS process = CONTAINING_RECORD(entry, INJ_PROCESS, Link);
		if (process->ProcessId == ProcessId)
		{
			return process;
		}
	}

	return NULL;
}

static void InjFreeUserBuffer(_In_ HANDLE ProcessId, _In_ PVOID Base)
{
	PVOID address = Base;
	SIZE_T size = 0;

	if (Base == NULL)
	{
		return;
	}

	if (PsGetCurrentProcessId() == ProcessId)
	{
		ZwFreeVirtualMemory(ZwCurrentProcess(), &address, &size, MEM_RELEASE);
		return;
	}
}

static BOOLEAN InjCopyFileName(_In_ PCWSTR Path, _In_ USHORT PathBytes, _Out_writes_(INJ_NAME_CHARS) WCHAR* FileName)
{
	USHORT chars;
	USHORT index;
	USHORT start;
	USHORT count;

	if (PathBytes < sizeof(WCHAR) || (PathBytes % sizeof(WCHAR)) != 0)
	{
		return FALSE;
	}

	chars = PathBytes / sizeof(WCHAR);
	if (chars >= INJDRV_MAX_PATH || Path[chars] != L'\0')
	{
		return FALSE;
	}

	start = 0;
	for (index = 0; index < chars; index++)
	{
		if (Path[index] == L'\\' || Path[index] == L'/')
		{
			start = (USHORT)(index + 1);
		}
	}

	if (start == 0 || start >= chars)
	{
		return FALSE;
	}

	count = (USHORT)(chars - start);
	if (count == 0 || count >= INJ_NAME_CHARS)
	{
		return FALSE;
	}

	RtlCopyMemory(FileName, Path + start, count * sizeof(WCHAR));
	FileName[count] = L'\0';
	return TRUE;
}

static BOOLEAN InjParentEndsWith(_In_ PCWSTR Path, _In_ USHORT PathBytes, _In_ PCWSTR Directory)
{
	UNICODE_STRING parent;
	USHORT chars;
	USHORT index;
	USHORT start = 0;

	if (PathBytes < sizeof(WCHAR) || (PathBytes % sizeof(WCHAR)) != 0)
	{
		return FALSE;
	}

	chars = PathBytes / sizeof(WCHAR);
	for (index = 0; index < chars; index++)
	{
		if (Path[index] == L'\\' || Path[index] == L'/')
		{
			start = (USHORT)(index + 1);
		}
	}

	if (start <= 1)
	{
		return FALSE;
	}

	parent.Buffer = (PWCH)Path;
	parent.Length = (USHORT)((start - 1) * sizeof(WCHAR));
	parent.MaximumLength = parent.Length;
	return InjEndsWithI(&parent, Directory);
}

typedef enum _INJ_DLL_SLOT {
	InjDllReject = 0,
	InjDllNative,
	InjDllWow64
} INJ_DLL_SLOT;

static INJ_DLL_SLOT InjClassifyDllPath(_In_ const INJDRV_DLL_PATH* Dll, _Out_writes_(INJ_NAME_CHARS) WCHAR* FileName)
{
	if (!InjCopyFileName(Dll->Path, Dll->Length, FileName))
	{
		return InjDllReject;
	}

	if (InjParentEndsWith(Dll->Path, Dll->Length, L"\\Windows\\System32"))
	{
		return InjDllNative;
	}

#if defined(_WIN64)
	if (InjParentEndsWith(Dll->Path, Dll->Length, L"\\Windows\\SysWOW64"))
	{
		return InjDllWow64;
	}
#endif

	return InjDllReject;
}

static void InjDestroyProcess(_In_ PINJ_PROCESS Process)
{
	RemoveEntryList(&Process->Link);
	InjFree(Process);
}

NTSTATUS InjInitialize(void)
{
	UNICODE_STRING routine;

	ExInitializeFastMutex(&g_Inj.Lock);
	InitializeListHead(&g_Inj.Processes);

	RtlInitUnicodeString(&routine, L"PsGetProcessWow64Process");
	g_Inj.GetWow64Process = (PFN_PS_GET_PROCESS_WOW64_PROCESS)MmGetSystemRoutineAddress(&routine);
	RtlInitUnicodeString(&routine, L"PsWrapApcWow64Thread");
	g_Inj.WrapApcWow64Thread = (PFN_PS_WRAP_APC_WOW64_THREAD)MmGetSystemRoutineAddress(&routine);
	RtlInitUnicodeString(&routine, L"PsIsProtectedProcess");
	g_Inj.IsProtectedProcess = (PFN_PS_IS_PROTECTED_PROCESS)MmGetSystemRoutineAddress(&routine);
	RtlInitUnicodeString(&routine, L"PsIsProtectedProcessLight");
	g_Inj.IsProtectedProcessLight = (PFN_PS_IS_PROTECTED_PROCESS)MmGetSystemRoutineAddress(&routine);
	return STATUS_SUCCESS;
}

void InjShutdown(void)
{
	ExAcquireFastMutex(&g_Inj.Lock);
	while (!IsListEmpty(&g_Inj.Processes))
	{
		PINJ_PROCESS process = CONTAINING_RECORD(g_Inj.Processes.Flink, INJ_PROCESS, Link);
		InjDestroyProcess(process);
	}
	g_Inj.NativeCount = 0;
	g_Inj.Wow64Count = 0;
	g_Inj.Enabled = FALSE;
	ExReleaseFastMutex(&g_Inj.Lock);
}

NTSTATUS InjSetDllList(_In_reads_bytes_(InputLength) const VOID* Input, _In_ ULONG InputLength)
{
	const INJDRV_SET_DLLS_INPUT* request;
	WCHAR native[INJDRV_MAX_DLLS][INJ_NAME_CHARS];
	WCHAR wow64[INJDRV_MAX_DLLS][INJ_NAME_CHARS];
	ULONG nativeCount = 0;
	ULONG wow64Count = 0;
	ULONG index;

	if (InputLength < sizeof(INJDRV_SET_DLLS_INPUT) || Input == NULL)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	request = (const INJDRV_SET_DLLS_INPUT*)Input;
	if (request->Count > INJDRV_MAX_DLLS)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(native, sizeof(native));
	RtlZeroMemory(wow64, sizeof(wow64));

	for (index = 0; index < request->Count; index++)
	{
		WCHAR fileName[INJ_NAME_CHARS];
		INJ_DLL_SLOT slot = InjClassifyDllPath(&request->Dlls[index], fileName);

		if (slot == InjDllReject)
		{
			return STATUS_OBJECT_NAME_INVALID;
		}
		if (slot == InjDllNative)
		{
			RtlCopyMemory(native[nativeCount], fileName, sizeof(fileName));
			nativeCount++;
		}
		else
		{
			RtlCopyMemory(wow64[wow64Count], fileName, sizeof(fileName));
			wow64Count++;
		}
	}

	ExAcquireFastMutex(&g_Inj.Lock);
	g_Inj.NativeCount = nativeCount;
	g_Inj.Wow64Count = wow64Count;
	RtlCopyMemory(g_Inj.NativeDlls, native, sizeof(native));
	RtlCopyMemory(g_Inj.Wow64Dlls, wow64, sizeof(wow64));
	ExReleaseFastMutex(&g_Inj.Lock);
	return STATUS_SUCCESS;
}

void InjSetEnabled(_In_ BOOLEAN Enabled)
{
	ExAcquireFastMutex(&g_Inj.Lock);
	g_Inj.Enabled = Enabled;
	ExReleaseFastMutex(&g_Inj.Lock);
	InjDbg("[injdrv] injection %s\n", Enabled ? "enabled" : "disabled");
}

static BOOLEAN InjCaptureSnapshot(
	_In_ HANDLE ProcessId,
	_In_ INJ_IMAGE_KIND Kind,
	_In_ PVOID ImageBase,
	_In_ SIZE_T ImageSize,
	_In_ BOOLEAN Wow64,
	_Out_writes_(INJDRV_MAX_DLLS) WCHAR Names[][INJ_NAME_CHARS],
	_Out_ PULONG NameCount,
	_Out_ PVOID* Kernel32Base,
	_Out_ SIZE_T* Kernel32Size,
	_Out_ PVOID* KernelBaseBase,
	_Out_ SIZE_T* KernelBaseSize)
{
	PINJ_PROCESS process;
	ULONG count;
	const WCHAR(*source)[INJ_NAME_CHARS];

	*NameCount = 0;
	*Kernel32Base = NULL;
	*Kernel32Size = 0;
	*KernelBaseBase = NULL;
	*KernelBaseSize = 0;

	ExAcquireFastMutex(&g_Inj.Lock);
	process = InjFindProcessLocked(ProcessId);
	if (process == NULL)
	{
		process = (PINJ_PROCESS)InjAllocate(sizeof(INJ_PROCESS));
		if (process == NULL)
		{
			ExReleaseFastMutex(&g_Inj.Lock);
			return FALSE;
		}

		process->ProcessId = ProcessId;
		process->Wow64 = Wow64;
		InsertTailList(&g_Inj.Processes, &process->Link);
	}

	if (Kind == InjImageKernel32)
	{
		process->Kernel32Base = ImageBase;
		process->Kernel32Size = ImageSize;
	}
	else
	{
		process->KernelBaseBase = ImageBase;
		process->KernelBaseSize = ImageSize;
	}

	*Kernel32Base = process->Kernel32Base;
	*Kernel32Size = process->Kernel32Size;
	*KernelBaseBase = process->KernelBaseBase;
	*KernelBaseSize = process->KernelBaseSize;

	if (Kind != InjImageKernel32 || process->Injected || !g_Inj.Enabled)
	{
		ExReleaseFastMutex(&g_Inj.Lock);
		return FALSE;
	}

	source = Wow64 ? g_Inj.Wow64Dlls : g_Inj.NativeDlls;
	count = Wow64 ? g_Inj.Wow64Count : g_Inj.NativeCount;
	if (count == 0)
	{
		ExReleaseFastMutex(&g_Inj.Lock);
		return FALSE;
	}

	process->Injected = TRUE;
	*NameCount = count;
	RtlCopyMemory(Names, source, count * sizeof(Names[0]));
	ExReleaseFastMutex(&g_Inj.Lock);
	return TRUE;
}

static NTSTATUS InjWriteUserPath(_In_ PCWSTR FileName, _Out_ PVOID* UserPath)
{
	SIZE_T chars = 0;
	SIZE_T bytes;
	SIZE_T size;
	PVOID base = NULL;
	NTSTATUS status;

	while (FileName[chars] != L'\0')
	{
		chars++;
	}
	bytes = (chars + 1) * sizeof(WCHAR);
	size = bytes;

	*UserPath = NULL;
	status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&base,
		0,
		&size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	__try
	{
		RtlCopyMemory(base, FileName, bytes);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		size = 0;
		ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
		return GetExceptionCode();
	}

	*UserPath = base;
	return STATUS_SUCCESS;
}

static void InjInjectProcess(
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Wow64,
	_In_reads_(NameCount) WCHAR Names[][INJ_NAME_CHARS],
	_In_ ULONG NameCount,
	_In_ PVOID Kernel32Base,
	_In_ SIZE_T Kernel32Size,
	_In_opt_ PVOID KernelBaseBase,
	_In_ SIZE_T KernelBaseSize)
{
	PVOID routine = NULL;
	NTSTATUS status;
	ULONG index;
	PKTHREAD thread = (PKTHREAD)PsGetCurrentThread();

	status = InjResolveLoadLibraryExW(
		Kernel32Base,
		Kernel32Size,
		KernelBaseBase,
		KernelBaseSize,
		&routine);
	if (!NT_SUCCESS(status) || routine == NULL)
	{
		InjDbg("[injdrv] LoadLibraryExW was not resolved: 0x%08X\n", status);
		return;
	}

	for (index = 0; index < NameCount; index++)
	{
		PVOID userPath = NULL;

		status = InjWriteUserPath(Names[index], &userPath);
		if (!NT_SUCCESS(status))
		{
			InjDbg("[injdrv] user path allocation failed: 0x%08X\n", status);
			continue;
		}

		if (!InjQueueUserLoadLibrary(thread, routine, userPath, Wow64))
		{
			InjFreeUserBuffer(ProcessId, userPath);
			InjDbg("[injdrv] APC queue failed for pid %Iu\n", (ULONG_PTR)ProcessId);
			continue;
		}

		InjDbg("[injdrv] queued LoadLibraryExW(\"%ws\") for pid %Iu\n", Names[index], (ULONG_PTR)ProcessId);
	}
}

void InjOnLoadImage(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
	BOOLEAN wow64;
	INJ_IMAGE_KIND kind;
	WCHAR names[INJDRV_MAX_DLLS][INJ_NAME_CHARS];
	ULONG nameCount = 0;
	PVOID kernel32 = NULL;
	SIZE_T kernel32Size = 0;
	PVOID kernelbase = NULL;
	SIZE_T kernelbaseSize = 0;

	if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL)
	{
		return;
	}
	if (ImageInfo->SystemModeImage || ImageInfo->ImageBase == NULL || ImageInfo->ImageSize == 0)
	{
		return;
	}
	if (InjIsSystemProcess(ProcessId))
	{
		return;
	}

	wow64 = InjIsCurrentProcessWow64();
	kind = InjClassifyImage(FullImageName, wow64);
	if (kind == InjImageOther)
	{
		return;
	}
	if (kind == InjImageKernel32 && InjIsCurrentProcessProtected())
	{
		return;
	}

	if (!InjCaptureSnapshot(
		ProcessId,
		kind,
		ImageInfo->ImageBase,
		ImageInfo->ImageSize,
		wow64,
		names,
		&nameCount,
		&kernel32,
		&kernel32Size,
		&kernelbase,
		&kernelbaseSize))
	{
		return;
	}

	InjInjectProcess(
		ProcessId,
		wow64,
		names,
		nameCount,
		kernel32,
		kernel32Size,
		kernelbase,
		kernelbaseSize);
}

void InjOnProcessExit(_In_ HANDLE ProcessId)
{
	PINJ_PROCESS process;

	ExAcquireFastMutex(&g_Inj.Lock);
	process = InjFindProcessLocked(ProcessId);
	if (process != NULL)
	{
		InjDestroyProcess(process);
	}
	ExReleaseFastMutex(&g_Inj.Lock);
}
