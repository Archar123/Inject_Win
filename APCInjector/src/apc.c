#include "apc.h"

typedef enum _INJ_KAPC_ENVIRONMENT
{
	InjOriginalApcEnvironment = 0,
	InjAttachedApcEnvironment = 1,
	InjCurrentApcEnvironment = 2,
	InjInsertApcEnvironment = 3
} INJ_KAPC_ENVIRONMENT;

typedef VOID (NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2);

typedef VOID (NTAPI* PINJ_KKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2);

typedef VOID(NTAPI* PINJ_KRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PKTHREAD Thread,
	_In_ INJ_KAPC_ENVIRONMENT Environment,
	_In_ PINJ_KKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PINJ_KRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ KPROCESSOR_MODE ProcessorMode,
	_In_opt_ PVOID NormalContext);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_In_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment);

static VOID NTAPI InjApcKernelRoutine(
	_In_ PRKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

static VOID NTAPI InjApcRundownRoutine(_In_ PRKAPC Apc)
{
	ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

static PVOID InjAllocateNonPaged(_In_ SIZE_T Size)
{
	return ExAllocatePoolWithTag(NonPagedPool, Size, INJ_POOL_TAG);
}

BOOLEAN InjQueueUserLoadLibrary(
	_In_ PKTHREAD Thread,
	_In_ PVOID LoadLibraryExW,
	_In_ PVOID UserPath,
	_In_ BOOLEAN Wow64)
{
	PVOID routine = LoadLibraryExW;
	PVOID context = UserPath;
	PRKAPC apc;
	ULONG flags = INJ_LOAD_IGNORE_CODE_AUTHZ_LEVEL | INJ_LOAD_LIBRARY_SEARCH_SYSTEM32;

#if defined(_WIN64)
	if (Wow64)
	{
		NTSTATUS status;

		if (g_Inj.WrapApcWow64Thread == NULL)
		{
			return FALSE;
		}

		routine = (PVOID)(ULONG_PTR)PtrToUlong(LoadLibraryExW);
		context = (PVOID)(ULONG_PTR)PtrToUlong(UserPath);
		status = g_Inj.WrapApcWow64Thread(&context, &routine);
		if (!NT_SUCCESS(status))
		{
			InjDbg("[injdrv] PsWrapApcWow64Thread failed: 0x%08X\n", status);
			return FALSE;
		}
	}
#else
	UNREFERENCED_PARAMETER(Wow64);
#endif

	apc = (PRKAPC)InjAllocateNonPaged(sizeof(KAPC));
	if (apc == NULL)
	{
		return FALSE;
	}

	KeInitializeApc(
		apc,
		Thread,
		InjOriginalApcEnvironment,
		InjApcKernelRoutine,
		InjApcRundownRoutine,
		(PKNORMAL_ROUTINE)routine,
		UserMode,
		context);

	if (!KeInsertQueueApc(apc, NULL, (PVOID)(ULONG_PTR)flags, IO_NO_INCREMENT))
	{
		ExFreePoolWithTag(apc, INJ_POOL_TAG);
		return FALSE;
	}

	return TRUE;
}
