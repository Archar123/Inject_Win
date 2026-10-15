#include "driver.h"
#include <stdarg.h>

INJ_GLOBALS g_Inj;

void InjDbg(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
	va_list args;

	va_start(args, Format);
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, args);
	va_end(args);
}

static VOID InjImageNotify(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
	InjOnLoadImage(FullImageName, ProcessId, ImageInfo);
}

static VOID InjProcessNotify(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo == NULL)
	{
		InjOnProcessExit(ProcessId);
	}
}

static VOID InjUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsRemoveLoadImageNotifyRoutine(InjImageNotify);
	PsSetCreateProcessNotifyRoutineEx(InjProcessNotify, TRUE);
	InjDeleteDevice();
	InjShutdown();
	InjDbg("[injdrv] unloaded\n");
}

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	status = InjInitialize();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = InjCreateDevice(DriverObject);
	if (!NT_SUCCESS(status))
	{
		InjShutdown();
		return status;
	}

	status = PsSetLoadImageNotifyRoutine(InjImageNotify);
	if (!NT_SUCCESS(status))
	{
		InjDeleteDevice();
		InjShutdown();
		return status;
	}

	status = PsSetCreateProcessNotifyRoutineEx(InjProcessNotify, FALSE);
	if (!NT_SUCCESS(status))
	{
		PsRemoveLoadImageNotifyRoutine(InjImageNotify);
		InjDeleteDevice();
		InjShutdown();
		return status;
	}

	DriverObject->DriverUnload = InjUnload;
	InjDbg("[injdrv] loaded\n");
	return STATUS_SUCCESS;
}
