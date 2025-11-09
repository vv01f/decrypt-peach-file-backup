#!/usr/bin/env python3
import sys
import base64
import hashlib
import argparse
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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

def encrypt_openssl_aes(plaintext: str, password: str, salt: bytes = None) -> str:
    """Encrypt plaintext using OpenSSL-compatible AES with random salt."""
    if salt is None:
        salt = get_random_bytes(8)

    key, iv = evp_bytes_to_key(password.encode("utf-8"), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # PKCS#7 padding
    pad_len = 16 - (len(plaintext.encode("utf-8")) % 16)
    padded = plaintext.encode("utf-8") + bytes([pad_len]) * pad_len

    encrypted = cipher.encrypt(padded)
    out = b"Salted__" + salt + encrypted
    return base64.b64encode(out).decode("utf-8")

def extract_salt_from_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    try:
        data = base64.b64decode(data)
    except Exception:
        pass

    if data.startswith(b"Salted__"):
        salt = data[8:16]
        print(f"✅ Found salt: {salt.hex()}")
        return salt
    else:
        print("⚠️ No 'Salted__' header found — file may not be in OpenSSL/CryptoJS format.")
        return None

def unescape_pgp(pgp_str: str) -> str:
    """Unescape any escaped newlines or quotes that may exist in JSON strings."""
    return pgp_str.replace("\\n", "\n").replace("\\r", "\r")

def export_pgp_keys(content: dict, base_filename: str):
    """Export PGP keys to files if present in the JSON structure."""
    pgp = content.get("pgp")
    if not pgp:
        print("ℹ️  No PGP key section found in decrypted content.")
        return

    private_key = pgp.get("privateKey")
    public_key = pgp.get("publicKey")

    if private_key:
        private_key = unescape_pgp(private_key)
        priv_path = Path(base_filename).with_suffix(".pgp-private.asc")
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(private_key)
        print(f"🔑 Exported PGP private key → {priv_path}")

    if public_key:
        public_key = unescape_pgp(public_key)
        pub_path = Path(base_filename).with_suffix(".pgp-public.asc")
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(public_key)
        print(f"🗝️  Exported PGP public key → {pub_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a file encrypted with CryptoJS/OpenSSL AES salted format."
    )
    
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt a Base64 AES-encrypted file (default output: decrypted-<file>).")
    mode.add_argument("-e", "--encrypt", action="store_true", help="Encrypt a JSON file to a Base64 AES-encrypted file (default output: encrypted-<file>).")
    
    parser.add_argument("filename", type=str, help="The file containing data to en- or decrypt.") #  (Base64-encrypted AES starts with 'U2FsdGVkX1...')
    parser.add_argument("password", type=str, help="Password used to en- or decrypt the file.")
    parser.add_argument("-o", "--output", type=str, default=None, help="Specify an optional output filename for the result.")
    parser.add_argument("-k", "--export-pgp-keys", action="store_true", help="If set, attempt to parse decrypted JSON and export PGP keys as .asc files.")
    parser.add_argument("-x", "--extract-salt", action="store_true", help="Extract and display the salt from the encrypted file.")
    parser.add_argument("-s", "--salt", type=str, help="Determine the salt to use for encryption, default is random.")

    args = parser.parse_args()

    if args.extract_salt and not args.decrypt:
        parser.error("--extract-salt can only be used with --decrypt")

    if args.salt and not args.encrypt:
        parser.error("--salt can only be used with --encrypt")

    file = Path(args.filename).name # args.filename
    password = args.password
    
    if args.encrypt:
        output_file = args.output or f"encrypted-{file}"

        if args.salt:
            salt = bytes.fromhex(args.salt)
        else:
            salt = get_random_bytes(8)

        try:
            with open(file, "r", encoding="utf-8") as f:
                json_data = f.read().strip()
            # Validate JSON
            parsed = json.loads(json_data)
            formatted = json.dumps(parsed, separators=(',', ':'), sort_keys=True)
        except Exception as e:
            print(f"❌ Error reading or parsing JSON file '{args.file}': {e}")
            sys.exit(1)

        try:
            encrypted_b64 = encrypt_openssl_aes(formatted, args.password, salt)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(encrypted_b64)
            print(f"🔒 Encrypted file written to {output_file}")
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            sys.exit(1)

    else : # args.decrypt:
        output_file = args.output or f"decrypted-{file}"

        if args.extract_salt:
            extract_salt_from_file(file)

        try:
            with open(file, "r", encoding="utf-8") as f:
                encrypted_text = f.read().strip()
        except Exception as e:
            print(f"Error reading file '{file}': {e}")
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

        if args.export_pgp_keys:
            try:
                content = json.loads(decrypted_text)
                export_pgp_keys(content, output_file)
            except json.JSONDecodeError:
                print("⚠️  Decrypted content is not valid JSON; cannot extract PGP keys.")
            except Exception as e:
                print(f"⚠️  Error exporting PGP keys: {e}")

if __name__ == "__main__":
    main()
