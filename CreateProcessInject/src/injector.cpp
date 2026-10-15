#include "injector.h"
#include "util.h"

#include <fstream>
#include <iostream>
#include <cstdio>

#define ILog(text, ...)       std::printf(text, __VA_ARGS__)
#define ILogError(text, ...)  do { std::printf(text, __VA_ARGS__); \
                                   std::cout << "Error: " << GetLastErrorAsString() << std::endl; } while (0)

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool InjectDLL(HANDLE hProc, const std::string& filepath, bool manualMap)
{
    if (!manualMap)
    {
        return LoadLibraryInject(hProc, filepath);
    }

    std::ifstream file(filepath, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cout << "Error while reading DLL file: " << filepath << std::endl;
        return false;
    }

    std::streampos size = file.tellg();
    auto memblock = new char[(size_t)size];
    file.seekg(0, std::ios::beg);
    file.read(memblock, size);
    file.close();

    BYTE* fileContent = (BYTE*)memblock;
    bool result = ManualMapDll(hProc, fileContent, (SIZE_T)size);

    delete[] memblock;
    return result;
}

bool LoadLibraryInject(HANDLE hProc, const std::string& dllpath)
{
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel == NULL)
    {
        ILogError("[DLL Injection] Failed to get kernel32.dll module address.\n");
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel, "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        ILogError("[DLL Injection] Failed to get LoadLibraryA address.\n");
        return false;
    }

    SIZE_T pathLen = dllpath.size() + 1;
    LPVOID pDLLPath = VirtualAllocEx(hProc, NULL, pathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pDLLPath == NULL)
    {
        ILogError("[DLL Injection] Failed to allocate memory for DLLPath in target process.\n");
        return false;
    }

    if (!WriteProcessMemory(hProc, pDLLPath, dllpath.c_str(), pathLen, NULL))
    {
        ILogError("[DLL Injection] Failed to write remote process memory.\n");
        VirtualFreeEx(hProc, pDLLPath, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                        pDLLPath, 0, NULL);
    if (hThread == NULL)
    {
        ILogError("[DLL Injection] Failed to create remote thread.\n");
        VirtualFreeEx(hProc, pDLLPath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pDLLPath, 0, MEM_RELEASE);

    if (exitCode == 0)
    {
        ILog("[DLL Injection] LoadLibraryA returned NULL inside target.\n");
        return false;
    }

    ILog("[DLL Injection] Successfully injected via LoadLibraryA (hModule=0x%p).\n", (void*)(uintptr_t)exitCode);
    return true;
}

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason)
{
    (void)FileSize;

    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
    {
        ILog("[DLL injection] Invalid file\n");
        return false;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH)
    {
        ILog("[DLL injection] Invalid platform.\n");
        return false;
    }

    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase)
    {
        ILogError("[DLL injection] Target process memory allocation failed.\n");
        return false;
    }

    DWORD oldp = 0;
    VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

    MANUAL_MAPPING_DATA data{};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
    SEHExceptionSupport = false;
#endif
    data.pbase = pTargetBase;
    data.fdwReasonParam = fdwReason;
    data.SEHSupport = SEHExceptionSupport;

    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr))
    {
        ILogError("[DLL injection] Can't write file header.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
    {
        if (pSectionHeader->SizeOfRawData)
        {
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                                    pSrcData + pSectionHeader->PointerToRawData,
                                    pSectionHeader->SizeOfRawData, nullptr))
            {
                ILogError("[DLL injection] Can't map sections.\n");
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc)
    {
        ILogError("[DLL injection] Target process mapping allocation failed.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
    {
        ILogError("[DLL injection] Can't write mapping.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode)
    {
        ILogError("[DLL injection] Memory shellcode allocation failed.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr))
    {
        ILogError("[DLL injection] Can't write shellcode.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    ILog("[DLL injection] Mapped DLL at %p\n", pTargetBase);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
    if (!hThread)
    {
        ILogError("[DLL injection] Thread creation failed.\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);

    HINSTANCE hCheck = NULL;
    while (!hCheck)
    {
        DWORD exitcode = 0;
        GetExitCodeProcess(hProc, &exitcode);
        if (exitcode != STILL_ACTIVE)
        {
            ILog("[DLL injection] Process crashed, exit code: 0x%x\n", exitcode);
            return false;
        }

        MANUAL_MAPPING_DATA data_checked{};
        ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;

        if (hCheck == (HINSTANCE)0x404040)
        {
            ILog("[DLL injection] Wrong mapping ptr.\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x505050)
        {
            ILog("[DLL injection] WARNING: Exception support failed!\n");
        }

        Sleep(10);
    }

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer == nullptr)
    {
        ILog("[DLL injection] Unable to allocate temp buffer\n");
        return false;
    }
    memset(emptyBuffer, 0, 1024 * 1024 * 20);

    if (ClearHeader)
    {
        if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr))
            ILogError("[DLL injection] WARNING: Can't clear HEADER\n");
    }

    if (ClearNonNeededSections)
    {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
        {
            if (pSectionHeader->Misc.VirtualSize)
            {
                if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
                    strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                    strcmp((char*)pSectionHeader->Name, ".reloc") == 0)
                {
                    WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                                       emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr);
                }
            }
        }
    }

    if (AdjustProtections)
    {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
        {
            if (pSectionHeader->Misc.VirtualSize)
            {
                DWORD old = 0;
                DWORD newP = PAGE_READONLY;

                if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
                    newP = PAGE_READWRITE;
                else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
                    newP = PAGE_EXECUTE_READ;

                VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                                 pSectionHeader->Misc.VirtualSize, newP, &old);
            }
        }
        DWORD old = 0;
        VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
    }

    WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr);
    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);

    free(emptyBuffer);
    return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
    if (!pData)
    {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta)
    {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
            {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
                {
                    if (RELOC_FLAG(*pRelativeInfo))
                    {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name)
        {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                else
                {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    bool ExceptionSupportFailed = false;

#ifdef _WIN64
    if (pData->SEHSupport)
    {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size)
        {
            if (!_RtlAddFunctionTable(
                    reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                    excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase))
            {
                ExceptionSupportFailed = true;
            }
        }
    }
#endif

    _DllMain(pBase, pData->fdwReasonParam, nullptr);

    if (ExceptionSupportFailed)
        pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
