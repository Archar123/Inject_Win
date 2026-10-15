#pragma once

#include "driver.h"

//
// Resolve kernel32!LoadLibraryExW in an image mapped into the current process.
// One forwarder step to kernelbase!LoadLibraryExW is followed. That is where
// the export points once kernelbase owns the loader implementation.
//
NTSTATUS InjResolveLoadLibraryExW(
	_In_ PVOID Kernel32Base,
	_In_ SIZE_T Kernel32Size,
	_In_opt_ PVOID KernelBaseBase,
	_In_ SIZE_T KernelBaseSize,
	_Out_ PVOID* Routine);
