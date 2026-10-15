#include "exports.h"

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	_In_ PVOID Base,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size);

typedef struct _INJ_EXPORT_FOUND {
	PVOID Address;
	BOOLEAN Forwarder;
	CHAR Module[64];
	CHAR Procedure[64];
} INJ_EXPORT_FOUND, *PINJ_EXPORT_FOUND;

static BOOLEAN InjRangeContains(_In_ SIZE_T ImageSize, _In_ ULONG Rva, _In_ SIZE_T Bytes)
{
	if (Rva == 0 || (SIZE_T)Rva >= ImageSize)
	{
		return FALSE;
	}

	return Bytes <= (ImageSize - (SIZE_T)Rva);
}

static PVOID InjRvaToPtr(_In_ PVOID ImageBase, _In_ SIZE_T ImageSize, _In_ ULONG Rva, _In_ SIZE_T Bytes)
{
	if (!InjRangeContains(ImageSize, Rva, Bytes))
	{
		return NULL;
	}

	return (PUCHAR)ImageBase + Rva;
}

static BOOLEAN InjCopyAscii(
	_In_reads_(Capacity) const CHAR* Source,
	_In_ SIZE_T Capacity,
	_Out_writes_(DestinationChars) CHAR* Destination,
	_In_ SIZE_T DestinationChars)
{
	SIZE_T index = 0;

	if (DestinationChars == 0)
	{
		return FALSE;
	}

	while (index < Capacity && Source[index] != '\0')
	{
		if (index + 1 >= DestinationChars)
		{
			Destination[0] = '\0';
			return FALSE;
		}

		Destination[index] = Source[index];
		index++;
	}

	Destination[index] = '\0';
	return index > 0;
}

static BOOLEAN InjAsciiStartsWithI(_In_z_ const CHAR* Text, _In_z_ const CHAR* Prefix)
{
	while (*Prefix != '\0')
	{
		CHAR text = *Text;
		CHAR prefix = *Prefix;

		if (text >= 'a' && text <= 'z')
		{
			text = (CHAR)(text - ('a' - 'A'));
		}
		if (prefix >= 'a' && prefix <= 'z')
		{
			prefix = (CHAR)(prefix - ('a' - 'A'));
		}
		if (text == '\0' || text != prefix)
		{
			return FALSE;
		}

		Text++;
		Prefix++;
	}

	return TRUE;
}

static BOOLEAN InjAsciiEqualI(_In_z_ const CHAR* Left, _In_z_ const CHAR* Right)
{
	while (*Left != '\0' && *Right != '\0')
	{
		CHAR left = *Left;
		CHAR right = *Right;

		if (left >= 'a' && left <= 'z')
		{
			left = (CHAR)(left - ('a' - 'A'));
		}
		if (right >= 'a' && right <= 'z')
		{
			right = (CHAR)(right - ('a' - 'A'));
		}
		if (left != right)
		{
			return FALSE;
		}

		Left++;
		Right++;
	}

	return *Left == '\0' && *Right == '\0';
}

static BOOLEAN InjSplitForwarder(
	_In_reads_(Capacity) const CHAR* Text,
	_In_ SIZE_T Capacity,
	_Inout_ PINJ_EXPORT_FOUND Found)
{
	SIZE_T dot = 0;
	SIZE_T length = 0;

	while (length < Capacity && Text[length] != '\0')
	{
		if (Text[length] == '.')
		{
			dot = length;
		}
		length++;
	}

	if (dot == 0 || dot + 1 >= length)
	{
		return FALSE;
	}

	if (!InjCopyAscii(Text, dot, Found->Module, RTL_NUMBER_OF(Found->Module)))
	{
		return FALSE;
	}

	return InjCopyAscii(Text + dot + 1, length - dot - 1, Found->Procedure, RTL_NUMBER_OF(Found->Procedure));
}

static NTSTATUS InjFindExport(
	_In_ PVOID ImageBase,
	_In_ SIZE_T ImageSize,
	_In_z_ const CHAR* Name,
	_Out_ PINJ_EXPORT_FOUND Found)
{
	NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;

	RtlZeroMemory(Found, sizeof(*Found));

	__try
	{
		ULONG exportSize = 0;
		const IMAGE_EXPORT_DIRECTORY* exports;
		const ULONG* names;
		const USHORT* ordinals;
		const ULONG* functions;
		ULONG exportRva;
		ULONG index;

		exports = (const IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(
			ImageBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			&exportSize);
		if (exports == NULL || exportSize < sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			status = STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}

		exportRva = (ULONG)((const UCHAR*)exports - (const UCHAR*)ImageBase);
		names = (const ULONG*)InjRvaToPtr(ImageBase, ImageSize, exports->AddressOfNames, sizeof(ULONG));
		ordinals = (const USHORT*)InjRvaToPtr(ImageBase, ImageSize, exports->AddressOfNameOrdinals, sizeof(USHORT));
		functions = (const ULONG*)InjRvaToPtr(ImageBase, ImageSize, exports->AddressOfFunctions, sizeof(ULONG));
		if (names == NULL || ordinals == NULL || functions == NULL)
		{
			status = STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}

		for (index = 0; index < exports->NumberOfNames; index++)
		{
			const CHAR* exportName;
			ULONG functionRva;
			USHORT ordinal;

			if (!InjRangeContains(ImageSize, exports->AddressOfNames + (index * sizeof(ULONG)), sizeof(ULONG)) ||
				!InjRangeContains(ImageSize, names[index], 1))
			{
				continue;
			}

			exportName = (const CHAR*)ImageBase + names[index];
			if (!InjAsciiEqualI(exportName, Name))
			{
				continue;
			}

			if (!InjRangeContains(ImageSize, exports->AddressOfNameOrdinals + (index * sizeof(USHORT)), sizeof(USHORT)))
			{
				status = STATUS_INVALID_IMAGE_FORMAT;
				__leave;
			}

			ordinal = ordinals[index];
			if (ordinal >= exports->NumberOfFunctions)
			{
				status = STATUS_INVALID_IMAGE_FORMAT;
				__leave;
			}

			functionRva = functions[ordinal];
			if (functionRva >= exportRva && functionRva < exportRva + exportSize)
			{
				const CHAR* forwarder = (const CHAR*)InjRvaToPtr(ImageBase, ImageSize, functionRva, 1);
				if (forwarder == NULL || !InjSplitForwarder(forwarder, exportSize, Found))
				{
					status = STATUS_INVALID_IMAGE_FORMAT;
					__leave;
				}

				Found->Forwarder = TRUE;
				status = STATUS_SUCCESS;
				__leave;
			}

			Found->Address = InjRvaToPtr(ImageBase, ImageSize, functionRva, 1);
			status = (Found->Address != NULL) ? STATUS_SUCCESS : STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}

	return status;
}

NTSTATUS InjResolveLoadLibraryExW(
	_In_ PVOID Kernel32Base,
	_In_ SIZE_T Kernel32Size,
	_In_opt_ PVOID KernelBaseBase,
	_In_ SIZE_T KernelBaseSize,
	_Out_ PVOID* Routine)
{
	INJ_EXPORT_FOUND found;
	NTSTATUS status;

	*Routine = NULL;

	if (Kernel32Base == NULL || Kernel32Size == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = InjFindExport(Kernel32Base, Kernel32Size, "LoadLibraryExW", &found);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!found.Forwarder)
	{
		*Routine = found.Address;
		return STATUS_SUCCESS;
	}

	if (KernelBaseBase == NULL || KernelBaseSize == 0)
	{
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	//
	// kernel32!LoadLibraryExW is a forwarder. Follow KERNELBASE directly, and
	// also an api-ms-win forwarder of the same procedure, one level only.
	//
	if (!InjAsciiEqualI(found.Module, "KERNELBASE") &&
		!InjAsciiStartsWithI(found.Module, "API-MS-WIN"))
	{
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	status = InjFindExport(KernelBaseBase, KernelBaseSize, found.Procedure, &found);
	if (!NT_SUCCESS(status) || found.Forwarder || found.Address == NULL)
	{
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	*Routine = found.Address;
	return STATUS_SUCCESS;
}
