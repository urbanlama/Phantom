#include "util.h"

namespace Phantom {
namespace Util {

PVOID getProcAddressByHash(HMODULE hModule, DWORD functionHash) {
    if (!hModule) return nullptr;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pdwAddressOfFunctions = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszFunctionName = (LPCSTR)((BYTE*)hModule + pdwAddressOfNames[i]);
        if (a_hash(pszFunctionName) == functionHash) {
            WORD wOrdinal = pwAddressOfNameOrdinales[i];
            return (PVOID)((BYTE*)hModule + pdwAddressOfFunctions[wOrdinal]);
        }
    }
    return nullptr;
}

DWORD getProcessIdByName(const std::string& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (_stricmp(processName.c_str(), processEntry.szExeFile) == 0) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }
    CloseHandle(hSnapshot);
    return 0;
}

DWORD findFirstThreadId(DWORD processId) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                CloseHandle(hThreadSnap);
                return te32.th32ThreadID;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
    return 0;
}

} // namespace Util
} // namespace Phantom 