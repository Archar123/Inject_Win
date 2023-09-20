﻿#pragma once

#include "s20.h"

constexpr UCHAR EncryptionKey[] = { 0x48, 0x7a, 0x65, 0x90, 0xd3, 0x44, 0x5e, 0x81, 0xda, 0xf1, 0x22, 0xd7, 0xf6, 0x90, 0xce, 0x5e };

template<SIZE_T N>
struct ENCRYPTED_STRING
{
	static_assert(N <= MAX_PATH * sizeof(WCHAR), "Maximum length exceeded");
	static constexpr ULONG32 Length = N;
	ULONG64 Nonce;
	const UCHAR EncryptedData[N];

	ENCRYPTED_STRING() = default;
};

constexpr ENCRYPTED_STRING<sizeof(L"DLL")> EncryptedDllString =
{
	0x58cb67fa57e51c25,
	{ 0xed, 0x15, 0x5d, 0x52, 0x3b, 0x85, 0x33, 0x8f }
};

constexpr ENCRYPTED_STRING<sizeof(L"EXE")> EncryptedExeString =
{
	0x58cb67fa57e51c26,
	{ 0x39, 0x6, 0x21, 0x27, 0x35, 0x48, 0x75, 0xf5 }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\DRM\\CUSTOMEXE")> EncryptedExeRegString =
{
	0x58cb67fa57e51c27,
	{ 0x11, 0x3c, 0xb5, 0xc6, 0x11, 0x84, 0x4e, 0xe2, 0xa9, 0x5d, 0x8, 0x3e, 0xd, 0xa4, 0x3f, 0xcb, 0x7e, 0x40, 0xf6, 0xa8, 0x7c, 0x1, 0xf4, 0xcb, 0xa1, 0xc5, 0x57, 0x9, 0xc4, 0x11, 0x2f, 0xe5, 0xf6, 0xaa, 0x1e, 0x5e, 0x1f, 0xe, 0xa, 0x6a, 0xab, 0x75, 0xb1, 0x78, 0xf6, 0x56, 0x1, 0xbb, 0xda, 0x21, 0xd8, 0xed, 0x68, 0x5c, 0x9b, 0xb6, 0x8d, 0x92, 0xd, 0x57, 0xb5, 0x86, 0x4a, 0xcc, 0x9f, 0x23, 0xe2, 0x7d, 0x8a, 0x85, 0x62, 0x6d, 0xfd, 0x44, 0xb0, 0xd, 0xe0, 0xe8, 0xcf, 0xe7, 0x9, 0x45, 0xfd, 0x38, 0x90, 0x9b, 0xf8, 0x37, 0x40, 0x64, 0x79, 0x8b, 0xe7, 0xe4, 0xd3, 0xc5, 0x88, 0x26, 0xd7, 0x54, 0x92, 0x10 }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\DRM")> EncryptedDllRegString =
{
	0x58cb67fa57e51c28,
	{ 0x7d, 0xf1, 0x45, 0xfd, 0x5, 0xee, 0xd, 0x8c, 0xde, 0x91, 0x2b, 0x15, 0xdf, 0x94, 0x50, 0xaf, 0xaa, 0x65, 0xb3, 0xf9, 0xb8, 0x3, 0x1f, 0xdc, 0xaa, 0xa, 0x7f, 0x7c, 0x51, 0xc7, 0x70, 0x56, 0xfe, 0x4f, 0x85, 0x90, 0x4, 0xd7, 0x4b, 0x37, 0xdf, 0x3b, 0x5c, 0xa6, 0xb, 0xce, 0x85, 0xb1, 0x71, 0xfd, 0xa7, 0xf6, 0xea, 0x24, 0x74, 0xd9, 0xe6, 0xb8, 0x64, 0x84, 0xc8, 0xd0, 0x2a, 0xa6, 0xaa, 0x9c, 0x54, 0x6e, 0x96, 0xbd, 0x98, 0xdd, 0xb6, 0xe9, 0xfe, 0x25, 0x5f, 0x92, 0xac, 0xdf, 0xdb, 0xee }
};

constexpr ENCRYPTED_STRING<sizeof(L"CSRSS.EXE")> EncryptedCsrssString =
{
	0x58cb67fa57e51c29,
	{ 0x2a, 0xf7, 0xb4, 0xee, 0x6a, 0x2, 0xb4, 0x96, 0x67, 0x95, 0xa1, 0x26, 0xcc, 0x8, 0xf6, 0x6f, 0x86, 0x35, 0x23, 0x5b }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\SystemRoot\\System32\\ntdll.dll")> EncryptedNtdllPathString =
{
	0x58cb67fa57e51c2a,
	{ 0x22, 0x32, 0xe1, 0x24, 0x3a, 0x38, 0xc3, 0x0d, 0x75, 0xc6, 0xaa, 0xca, 0xf9, 0xcd, 0x2c, 0x50, 0x94, 0xdc, 0xe4, 0x74, 0x77, 0xd0, 0xf4, 0xbb, 0xa3, 0x53, 0x86, 0xe1, 0x1d, 0x15, 0x16, 0x3b, 0xc3, 0x4d, 0xd9, 0xb6, 0xfe, 0xa8, 0x02, 0xd8, 0xe7, 0x7e, 0xf0, 0xb4, 0xca, 0x40, 0xbf, 0xc8, 0x33, 0x7c, 0x51, 0xcf, 0x6e, 0x35, 0x22, 0x91, 0x6d, 0x62, 0xff, 0x92, 0xb1, 0x89 }
};

constexpr ENCRYPTED_STRING<sizeof("NtCreateThreadEx")> EncryptedNtCreateThreadExString =
{
	0x58cb67fa57e51c2b,
	{ 0xe4, 0x44, 0x1c, 0x03, 0x8f, 0x5b, 0x4c, 0x09, 0x50, 0x7d, 0x4a, 0xcd, 0xce, 0x90, 0x35, 0xf8, 0x2c }
};

constexpr ENCRYPTED_STRING<sizeof("NtResumeThread")> EncryptedNtResumeThreadString =
{
	0x58cb67fa57e51c2c,
	{ 0xf7, 0x40, 0x6b, 0x73, 0x9a, 0x14, 0x4f, 0xc9, 0x89, 0xde, 0x02, 0x1f, 0xaa, 0xc3, 0xb7 }
};

constexpr ENCRYPTED_STRING<sizeof("NtTerminateThread")> EncryptedNtTerminateThreadString =
{
	0x58cb67fa57e51c2d,
	{ 0x21, 0x3c, 0x5a, 0x5b, 0x97, 0xd4, 0xd0, 0xa0, 0x03, 0x5c, 0xc9, 0x05, 0x84, 0x55, 0xb9, 0x0f, 0xb8, 0x73 }
};

constexpr ENCRYPTED_STRING<sizeof("NtProtectVirtualMemory")> EncryptedNtProtectVirtualMemoryString =
{
	0x58cb67fa57e51c2e,
	{ 0xb1, 0xa2, 0x13, 0x8c, 0xa1, 0xd2, 0xe5, 0xf3, 0x2c, 0xc9, 0xf6, 0x4c, 0x92, 0x03, 0x57, 0x2b, 0xf5, 0x04, 0xf3, 0x50, 0x66, 0x05, 0x58 }
};

/* // String no longer used, but this nonce is taken
constexpr ENCRYPTED_STRING<sizeof("NtRemoveIoCompletion")> EncryptedNtRemoveIoCompletionString =
{
	0x58cb67fa57e51c2f,
	{ 0x48, 0x94, 0x1e, 0xe5, 0xac, 0xa7, 0xc3, 0x32, 0x10, 0x29, 0xf1, 0x4f, 0x02, 0x17, 0x8c, 0x1b, 0x82, 0x4e, 0x84, 0x37, 0x9c }
};
*/

constexpr ENCRYPTED_STRING<sizeof("RtlAddFunctionTable")> EncryptedRtlAddFunctionTableString =
{
	0x58cb67fa57e51c30,
	{ 0xe1, 0xfa, 0x6a, 0x5f, 0x5c, 0xeb, 0xfc, 0xaf, 0xe2, 0xc5, 0x26, 0x18, 0xef, 0x1e, 0x29, 0x59, 0xd3, 0x81, 0x58, 0x8b }
};

constexpr ENCRYPTED_STRING<sizeof("DbgUiRemoteBreakin")> EncryptedDbgUiRemoteBreakinString =
{
	0x58cb67fa57e51c31,
	{ 0x36, 0xbb, 0x0c, 0x49, 0xfa, 0x0f, 0x8c, 0x4f, 0xc8, 0xe1, 0x24, 0x40, 0x42, 0xb0, 0x52, 0x7b, 0xdc, 0x3a, 0x46 }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\SystemRoot\\SysWOW64\\")> EncryptedSysWOW64PathString =
{
	0x58cb67fa57e51c32,
	{ 0x9c, 0xf8, 0xa5, 0x3e, 0x61, 0x87, 0xca, 0x2b, 0x7e, 0x30, 0x1d, 0x4c, 0xfb, 0xea, 0x71, 0xe8, 0x38, 0x40, 0x62, 0x55, 0x11, 0x66, 0x38, 0x37, 0x9f, 0x80, 0x71, 0x2d, 0x03, 0x0f, 0xf1, 0x06, 0x8f, 0x16, 0x51, 0x11, 0x5e, 0xb1, 0xe9, 0x13, 0xe6, 0xfc, 0x61, 0x5c }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\SystemRoot\\System32\\")> EncryptedSystem32PathString =
{
	0x58cb67fa57e51c33,
	{ 0xbe, 0x71, 0x86, 0x54, 0xdc, 0x0a, 0x9f, 0xd1, 0xca, 0xc2, 0xf4, 0xc9, 0x4d, 0xb8, 0xa9, 0xb9, 0xa8, 0x72, 0x4c, 0x7c, 0xa9, 0x08, 0xdc, 0xf6, 0xbe, 0xdf, 0xc9, 0x6e, 0x19, 0x84, 0x30, 0x67, 0xd7, 0x59, 0x43, 0x42, 0x18, 0x2c, 0x13, 0x37, 0x4a, 0x88, 0xf8, 0x96 }
};

constexpr ENCRYPTED_STRING<sizeof(L"ntdll.dll")> EncryptedNtdllString =
{
	0x58cb67fa57e51c34,
	{ 0x1d, 0xee, 0xf0, 0x6a, 0x0d, 0x5e, 0xde, 0x27, 0xc2, 0x3f, 0xf3, 0x2a, 0xc4, 0x09, 0x6c, 0x89, 0x87, 0x6c, 0x4d, 0x5f }
};

constexpr ENCRYPTED_STRING<sizeof(L"EXENAME")> EncryptedExeNameString =
{
	0x58cb67fa57e51c35,
	{ 0x9f, 0xa0, 0x61, 0x4f, 0xec, 0xf7, 0x41, 0xc3, 0x77, 0x25, 0xf1, 0xd6, 0xd9, 0x5f, 0xdc, 0xf0 }
};

constexpr ENCRYPTED_STRING<sizeof(L"WAIT")> EncryptedWaitString =
{
	0x58cb67fa57e51c36,
	{ 0x44, 0x87, 0x83, 0xf2, 0x69, 0x6d, 0x9b, 0x14, 0x5d, 0xb5 }
};

constexpr ENCRYPTED_STRING<sizeof(L"DELETE")> EncryptedDeleteString =
{
	0x58cb67fa57e51c37,
	{ 0x4f, 0x62, 0x84, 0x6c, 0x5a, 0xf4, 0x54, 0x31, 0x4c, 0xc3, 0xff, 0x26, 0xe8, 0x72 }
};

constexpr ENCRYPTED_STRING<sizeof(L"DRVDEL")> EncryptedDriverDeleteString =
{
	0x58cb67fa57e51c38,
	{ 0x25, 0x40, 0x13, 0x9D, 0xC9, 0x09, 0x1A, 0x86, 0x85, 0x7E, 0x31, 0xF9, 0x95, 0x21 }
};

constexpr ENCRYPTED_STRING<sizeof("EtwpCreateEtwThread")> EncryptedEtwpCreateEtwThreadString =
{
	0x58cb67fa57e51c39,
	{ 0xCA, 0x17, 0xF3, 0x1E, 0x88, 0x24, 0x5A, 0xC6, 0x7B, 0x4B, 0x8E, 0x42, 0x06, 0xED, 0xBC, 0x63, 0xF0, 0x22, 0x51, 0x15 }
};

constexpr ENCRYPTED_STRING<sizeof("RtlActivateActivationContextEx")> EncryptedRtlActivateActivationContextExString =
{
	0x58cb67fa57e51c3a,
	{ 0xF6, 0x64, 0x4E, 0xA3, 0x04, 0xDA, 0x67, 0x09, 0xC0, 0xDF, 0x4C, 0x14, 0x78, 0x7C, 0x73, 0x66, 0x8F, 0x02, 0x44, 0xBA, 0x62, 0xDD, 0x13, 0xED, 0x43, 0x82, 0xF0, 0xE4, 0xE4, 0xEB, 0x47 }
};

constexpr ENCRYPTED_STRING<sizeof("RtlCreateActivationContext")> EncryptedRtlCreateActivationContextString =
{
	0x58cb67fa57e51c3b,
	{ 0x58, 0x73, 0x9B, 0x3B, 0xB4, 0x6F, 0x96, 0x89, 0x48, 0x4A, 0xF1, 0x91, 0x37, 0x75, 0xE3, 0x7A, 0x03, 0x9C, 0xAC, 0x9D, 0x82, 0xE9, 0x24, 0xC3, 0x1E, 0x6E, 0xDE }
};

constexpr ENCRYPTED_STRING<sizeof("RtlQueryActivationContextApplicationSettings")> EncryptedRtlQueryActivationContextApplicationSettingsString =
{
	0x58cb67fa57e51c3c,
	{ 0x8C, 0x56, 0x9C, 0xEC, 0x5C, 0xD9, 0x38, 0x0D, 0xF5, 0x63, 0x56, 0x99, 0x31, 0x84, 0xA9, 0x6B, 0x39, 0x0A, 0x4B, 0x37, 0x79, 0xE4, 0x93, 0xF5, 0x12, 0x5B, 0x18, 0x63, 0x1F, 0xB1, 0x1B, 0xDA, 0x9A, 0x57, 0x75, 0xF1, 0x13, 0x11, 0xA2, 0x49, 0xC3, 0x16, 0x11, 0x16, 0x6E }
};

constexpr ENCRYPTED_STRING<sizeof("RtlValidateHeap")> EncryptedRtlValidateHeapString =
{
	0x58cb67fa57e51c3d,
	{ 0x50, 0x0C, 0xAA, 0x00, 0x2B, 0xFA, 0x2B, 0x47, 0xD2, 0x35, 0xF6, 0x3D, 0x82, 0xB1, 0x16, 0x3B }
};

constexpr ENCRYPTED_STRING<sizeof("TpStartAsyncIoOperation")> EncryptedTpStartAsyncIoOperationString =
{
	0x58cb67fa57e51c3e,
	{ 0x4D, 0x84, 0xC1, 0x40, 0x52, 0xEB, 0x94, 0x1E, 0x90, 0x8F, 0x45, 0xD8, 0x18, 0x00, 0x0F, 0xF4, 0xBD, 0x04, 0x1C, 0x90, 0x5E, 0x15, 0xDD, 0x3A }
};

constexpr ENCRYPTED_STRING<sizeof("TpWaitForWork")> EncryptedTpWaitForWorkString =
{
	0x58cb67fa57e51c3f,
	{ 0x0E, 0xDB, 0x85, 0x55, 0x61, 0xCD, 0xBF, 0x88, 0x30, 0xF4, 0xF6, 0x9E, 0xBC, 0x45 }
};

constexpr ENCRYPTED_STRING<sizeof("WinSqmEventWrite")> EncryptedWinSqmEventWriteString =
{
	0x58cb67fa57e51c40,
	{ 0xDA, 0x61, 0x05, 0xFA, 0xDD, 0xEE, 0x9F, 0x5E, 0xBC, 0x8A, 0x09, 0x6B, 0xA2, 0xA8, 0xB5, 0x01, 0x80 }
};

constexpr ENCRYPTED_STRING<sizeof("PsSetCreateThreadNotifyRoutine")> EncryptedPsSetCreateThreadNotifyRoutineString =
{
	0x58cb67fa57e51c41,
	{ 0xCC, 0x8F, 0x89, 0xBF, 0xA6, 0x1F, 0xAE, 0xCD, 0x50, 0x04, 0x1D, 0x14, 0x73, 0x06, 0x08, 0x45, 0xB2, 0xCD, 0x69, 0xC8, 0x98, 0x1E, 0x6B, 0xAC, 0x07, 0x03, 0xDD, 0xB4, 0x48, 0x94, 0xDA }
};

constexpr ENCRYPTED_STRING<sizeof("PsLoadedModuleResource")> EncryptedPsLoadedModuleResourceString =
{
	0x58cb67fa57e51c42,
	{ 0xAF, 0xDA, 0xB9, 0xFB, 0xFD, 0x81, 0x6F, 0x30, 0x23, 0x09, 0xF0, 0x69, 0xB6, 0xEE, 0xF1, 0x01, 0x49, 0x34, 0x9B, 0x7A, 0x2E, 0x53, 0x68 }
};

constexpr ENCRYPTED_STRING<sizeof(L"AES")> EncryptedAESString =
{
	0x58cb67fa57e51c43,
	{ 0x7B, 0x95, 0x08, 0x17, 0x14, 0x96, 0xFC, 0x87 }
};

constexpr ENCRYPTED_STRING<sizeof(L"BlockLength")> EncryptedBlockLengthString =
{
	0x58cb67fa57e51c44,
	{ 0x42, 0x61, 0xF0, 0x32, 0x28, 0x5A, 0x61, 0xE1, 0x12, 0x08, 0xF2, 0xE2, 0xBB, 0x3A, 0x2E, 0x86, 0xAB, 0xBF, 0xEE, 0x8E, 0x20, 0xFB, 0xE1, 0x87 }
};

constexpr ENCRYPTED_STRING<sizeof(L"ChainingMode")> EncryptedChainingModeString =
{
	0x58cb67fa57e51c45,
	{ 0xE6, 0x49, 0x96, 0x95, 0x6B, 0x88, 0xD3, 0x87, 0x10, 0x1E, 0xB7, 0xA1, 0x16, 0x4C, 0x86, 0xA3, 0xE2, 0x40, 0x5F, 0x9C, 0xF2, 0x64, 0x3D, 0xB9, 0x0C, 0xD0 }
};

constexpr ENCRYPTED_STRING<sizeof(L"ChainingModeCBC")> EncryptedChainingModeCBCString =
{
	0x58cb67fa57e51c46,
	{ 0xDD, 0x47, 0x02, 0x42, 0x73, 0x16, 0xC8, 0x2B, 0x4D, 0x49, 0x67, 0x6B, 0xC1, 0x1D, 0x8E, 0xD5, 0x8B, 0x8A, 0xC1, 0x5A, 0xBB, 0xFA, 0xA7, 0x82, 0xF7, 0x06, 0xFD, 0x5E, 0x82, 0x90, 0xDE, 0xD4 }
};

constexpr ENCRYPTED_STRING<sizeof(L"ObjectLength")> EncryptedObjectLengthString =
{
	0x58cb67fa57e51c47,
	{ 0x4C, 0xA0, 0x35, 0x77, 0x8C, 0x2E, 0xC9, 0x42, 0xC9, 0x0B, 0x08, 0xD6, 0xCF, 0x6A, 0x7A, 0x6B, 0x55, 0x9A, 0x79, 0x7C, 0xD3, 0xE3, 0x4A, 0xD4, 0x64, 0x50 }
};

template<SIZE_T N>
FORCEINLINE
VOID
DecryptString(
	_In_ CONST ENCRYPTED_STRING<N>& Encrypted,
	_Out_ PCHAR Decrypted
	)
{
	constexpr ULONG32 Length = Encrypted.Length;
	PUCHAR Buffer[Length];

	RtlCopyMemory(Buffer, Encrypted.EncryptedData, Length);

	if (s20_crypt(const_cast<PUCHAR>(EncryptionKey),
		S20_KEYLEN_128,
		PUCHAR(&Encrypted.Nonce),
		0,
		reinterpret_cast<PUCHAR>(Buffer),
		Length) != S20_SUCCESS)
	{
		NT_ASSERT(FALSE);
	}

	RtlCopyMemory(Decrypted, Buffer, Length);
	RtlSecureZeroMemory(Buffer, Length);
}

template<SIZE_T N>
FORCEINLINE
VOID
DecryptString(
	_In_ CONST ENCRYPTED_STRING<N>& Encrypted,
	_Out_ PWCHAR Decrypted
	)
{
	DecryptString(Encrypted, reinterpret_cast<PCHAR>(Decrypted));
}
