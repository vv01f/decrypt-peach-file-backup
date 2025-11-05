#!/usr/bin/env python3
import sys
import base64
import hashlib
import argparse
from Crypto.Cipher import AES

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
    """Pure Python implementation of OpenSSL EVP_BytesToKey using MD5."""
    d = b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d[-16:] + password + salt).digest() if d else hashlib.md5(password + salt).digest()
        d += d_i
    key = d[:key_len]
    iv = d[key_len:key_len + iv_len]
    return key, iv

def decrypt_openssl_aes(encrypted_b64: str, password: str) -> bytes:
    """Decrypt a Base64 string starting with 'Salted__' (CryptoJS/OpenSSL compatible)."""
    encrypted_bytes = base64.b64decode(encrypted_b64)
    if not encrypted_bytes.startswith(b"Salted__"):
        raise ValueError("Invalid ciphertext: missing 'Salted__' header (not OpenSSL format).")

    salt = encrypted_bytes[8:16]
    ciphertext = encrypted_bytes[16:]

    key, iv = evp_bytes_to_key(password.encode("utf-8"), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Remove PKCS#7 padding
    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding in decrypted data.")
    return decrypted[:-pad_len]

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a file encrypted with CryptoJS/OpenSSL AES salted format."
    )
    parser.add_argument(
        "encrypted_file",
        type=str,
        help="Path to the file containing Base64-encrypted AES data (starts with 'U2FsdGVkX1...')."
    )
    parser.add_argument(
        "password",
        type=str,
        help="Password used to encrypt the file."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output filename for decrypted content. Defaults to 'decrypted-<encrypted_file>'."
    )

    args = parser.parse_args()

    encrypted_file = args.encrypted_file
    password = args.password
    output_file = args.output or f"decrypted-{encrypted_file}"

    try:
        with open(encrypted_file, "r", encoding="utf-8") as f:
            encrypted_text = f.read().strip()
    except Exception as e:
        print(f"Error reading file '{encrypted_file}': {e}")
        sys.exit(1)

    try:
        decrypted_bytes = decrypt_openssl_aes(encrypted_text, password)
        decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
        print(f"✅ Decrypted content written to {output_file}")
    except Exception as e:
        print(f"Error writing file '{output_file}': {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
