#include "driver.h"
#include <initguid.h>
#include <wdmsec.h>

DEFINE_GUID(GUID_DEVCLASS_INJDRV,
	0x8f4c2a11, 0x6b3e, 0x4d19, 0x9c, 0x27, 0x51, 0xa8, 0xe4, 0xb0, 0x7c, 0x2d);

static NTSTATUS InjCompleteIrp(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

_Function_class_(DRIVER_DISPATCH)
static NTSTATUS InjDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return InjCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

_Function_class_(DRIVER_DISPATCH)
static NTSTATUS InjDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return InjCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

_Function_class_(DRIVER_DISPATCH)
static NTSTATUS InjDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	PIO_STACK_LOCATION stack;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG code;

	UNREFERENCED_PARAMETER(DeviceObject);

	stack = IoGetCurrentIrpStackLocation(Irp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (code)
	{
	case IOCTL_INJDRV_SET_DLLS:
		status = InjSetDllList(
			Irp->AssociatedIrp.SystemBuffer,
			stack->Parameters.DeviceIoControl.InputBufferLength);
		break;
	case IOCTL_INJDRV_ENABLE:
		InjSetEnabled(TRUE);
		status = STATUS_SUCCESS;
		break;
	case IOCTL_INJDRV_DISABLE:
		InjSetEnabled(FALSE);
		status = STATUS_SUCCESS;
		break;
	default:
		break;
	}

	return InjCompleteIrp(Irp, status, 0);
}

NTSTATUS InjCreateDevice(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(INJDRV_NT_DEVICE_NAME);
	UNICODE_STRING symlink = RTL_CONSTANT_STRING(INJDRV_DOS_DEVICE_NAME);
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	PDEVICE_OBJECT device = NULL;
	NTSTATUS status;
	ULONG index;

	status = IoCreateDeviceSecure(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&sddl,
		&GUID_DEVCLASS_INJDRV,
		&device);
	if (!NT_SUCCESS(status))
	{
		InjDbg("[injdrv] IoCreateDeviceSecure failed: 0x%08X\n", status);
		return status;
	}

	status = IoCreateSymbolicLink(&symlink, &deviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		InjDbg("[injdrv] IoCreateSymbolicLink failed: 0x%08X\n", status);
		return status;
	}

	for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; index++)
	{
		DriverObject->MajorFunction[index] = InjDispatchUnsupported;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = InjDispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = InjDispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = InjDispatchDeviceControl;

	device->Flags |= DO_BUFFERED_IO;
	device->Flags &= ~DO_DEVICE_INITIALIZING;
	g_Inj.DeviceObject = device;
	return STATUS_SUCCESS;
}

void InjDeleteDevice(void)
{
	UNICODE_STRING symlink = RTL_CONSTANT_STRING(INJDRV_DOS_DEVICE_NAME);

	IoDeleteSymbolicLink(&symlink);
	if (g_Inj.DeviceObject != NULL)
	{
		IoDeleteDevice(g_Inj.DeviceObject);
		g_Inj.DeviceObject = NULL;
	}
}
