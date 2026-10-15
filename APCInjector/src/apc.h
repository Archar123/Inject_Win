#pragma once

#include "driver.h"

//
// Queue a user APC whose normal routine is LoadLibraryExW.
// UserPath must stay valid until the APC has run. The caller owns that buffer.
//
BOOLEAN InjQueueUserLoadLibrary(
	_In_ PKTHREAD Thread,
	_In_ PVOID LoadLibraryExW,
	_In_ PVOID UserPath,
	_In_ BOOLEAN Wow64);
