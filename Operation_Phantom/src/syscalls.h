#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include "techniques/SyscallData.h"

// Deklariert die globalen Syscall-Datenstrukturen, die in syscall_stub.asm definiert sind.
// Der C++ Code kann so darauf zugreifen.
extern "C" {
    extern SyscallData g_sNtAllocateVirtualMemory;
    extern SyscallData g_sNtWriteVirtualMemory;
    extern SyscallData g_sNtCreateThreadEx;
    extern SyscallData g_sNtUnmapViewOfSection;
    extern SyscallData g_sNtQueryInformationProcess;
    extern SyscallData g_sNtQueueApcThread;
    extern SyscallData g_sNtGetContextThread;
    extern SyscallData g_sNtSetContextThread;
    extern SyscallData g_sNtResumeThread;
}

// Deklariert die externen Assembler-Funktionen für Typsicherheit im C++ Code.
// Dies ist die einzige Stelle, an der diese Deklarationen benötigt werden.
typedef VOID(NTAPI* PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);

extern "C" {
    NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS SyscallNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS SyscallNtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    NTSTATUS SyscallNtUnmapViewOfSection(HANDLE, PVOID);
    NTSTATUS SyscallNtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    NTSTATUS SyscallNtQueueApcThread(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID);
    NTSTATUS SyscallNtGetContextThread(HANDLE, PCONTEXT);
    NTSTATUS SyscallNtSetContextThread(HANDLE, PCONTEXT);
    NTSTATUS SyscallNtResumeThread(HANDLE, PULONG);
}


/**
 * @brief Initialisiert die globalen Syscall-Datenstrukturen.
 * 
 * Lädt die Syscall-IDs aus einer sauberen Kopie von ntdll.dll, um Hooking zu umgehen.
 * Diese Funktion muss einmal zu Beginn des Programms aufgerufen werden.
 * 
 * @param hNtdll Ein Handle zu einer sauberen, ungehookten ntdll.dll.
 * @return true, wenn alle Syscalls erfolgreich aufgelöst wurden, andernfalls false.
 */
bool InitializeSyscalls(HMODULE hNtdll);

#endif // SYSCALLS_H 