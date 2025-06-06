#ifndef SYSCALL_DATA_H
#define SYSCALL_DATA_H

#include <windows.h>

// Zentrale Definition der Struktur für indirekte Syscalls.
// KORREKTUR: Enthält jetzt nur noch die Syscall-ID.
struct SyscallData {
    DWORD syscall_id;
    // PVOID syscall_address; // Nicht mehr benötigt
};

#endif // SYSCALL_DATA_H 