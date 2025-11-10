#!/usr/bin/env python3
# AES (OpenSSL-compatible) Encrypt/Decrypt Tool for use with Peach Bitcoin file backups
import sys
import base64
import hashlib
import argparse
import json
import logging
import getpass
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from importlib.metadata import metadata, PackageNotFoundError

if sys.version_info >= (3, 11):
    import tomllib as tomli  # built-in in Python starting 3.11
else:
    try:
        import tomli  # external backport for older Python
    except ImportError:
        tomli = None

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
    """Pure Python implementation of OpenSSL EVP_BytesToKey using MD5 (MD5, insecure for new systems)."""
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
    if pad_len < 1 or pad_len > 16 or decrypted[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding in decrypted data.")
    return decrypted[:-pad_len]

def encrypt_openssl_aes(plaintext: str, password: str, salt: bytes = None) -> str:
    """Encrypt plaintext using OpenSSL-compatible AES with random salt."""
    if salt is None:
        salt = get_random_bytes(8)

    key, iv = evp_bytes_to_key(password.encode("utf-8"), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # PKCS#7 padding
    pad_len = 16 - (len(plaintext.encode("utf-8")) % 16)
    log.debug(f"Padding length: {pad_len}")
    padded = plaintext.encode("utf-8") + bytes([pad_len]) * pad_len

    encrypted = cipher.encrypt(padded)
    out = b"Salted__" + salt + encrypted
    return base64.b64encode(out).decode("utf-8")

def extract_salt_from_file(file: Path):
    with file.open("rb") as f:
        data = f.read()

    try:
        data = base64.b64decode(data)
    except Exception:
        pass

    if data.startswith(b"Salted__"):
        salt = data[8:16]
        log.info(f"🧂 Salt used: {salt.hex()}")
        return salt
    else:
        log.error("⚠️ No 'Salted__' header found — file may not be in OpenSSL/CryptoJS format.")
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

def fixcase_keys(d):
    """Recursively capitalize dictionary keys (first letter uppercase, rest lowercase)."""
    if not isinstance(d, dict):
        return d
    return {k.capitalize(): fixcase_keys(v) for k, v in d.items()}

def get_version_info():
    fallback = {
        "Name": "Unlocker",
        "Version": "?0.1.2?",
        "License": "MIT",
        "Description": "Decrypt and encrypt AES files encrypted with CryptoJS/OpenSSL salted format for use with Peach Bitcoin backup files.",
    }
    pyproject = Path(__file__).parent / "myproject.toml"
    if not pyproject.exists() or not tomli:
        log.info("Using fallback version info")
        return fallback
    elif pyproject.exists() and tomli:
        try:
            with pyproject.open("rb") as f:
                data = fixcase_keys(tomli.load(f))
            metadata = data.get("Project", {})
            license = metadata.get("License", fallback["License"])
            license = license.get("Text") if isinstance(license, dict) and license.get("Text") else license if isinstance(license, str) else fallback["License"]

            return {
                "Name": metadata.get("Name", fallback["Name"]),
                "Version": metadata.get("Version", fallback["Version"]),
                "License": license,
                "Description": fallback["Description"]
            }
        except Exception:
            return fallback

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt or encrypt a file compatible with OpenSSL AES (Salted__ header, Base64).",
        epilog="""Examples:
  Decrypt a backup:
    decrypt.py -d peach-account.json

  Extract the salt:
    decrypt.py -x -d peach-account.json

  Encrypt JSON with custom salt:
    decrypt.py -e decrypted-peach-account.json -s 76067517a6f30d01
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    version_info = get_version_info()

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt a Base64 AES-encrypted file (default output: decrypted-<file>).")
    mode.add_argument("-e", "--encrypt", action="store_true", help="Encrypt a JSON file to a Base64 AES-encrypted file (default output: encrypted-<file>).")

    parser.add_argument("filename", type=str, help="The file containing data to en- or decrypt.") #  (Base64-encrypted AES starts with 'U2FsdGVkX1...')
    parser.add_argument("-p", "--password", type=str, help="Password used to en- or decrypt the file.")
    parser.add_argument("-o", "--output", type=str, default=None, help="Specify an optional output filename for the result.")
    parser.add_argument("-k", "--export-pgp-keys", action="store_true", help="If set, attempt to parse decrypted JSON and export PGP keys as .asc files.")
    parser.add_argument("-x", "--extract-salt", action="store_true", help="Extract and display the salt from the encrypted file.")
    parser.add_argument("-s", "--salt", type=str, help="Determine the salt to use for encryption, default is random.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug-level logging)")
    parser.add_argument('--version', action='version', version=f"{version_info['Name']} v{version_info['Version']} - License: {version_info['License']}\n\n{version_info['Description']}")

    args = parser.parse_args()


    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.extract_salt and not args.decrypt:
        parser.error("--extract-salt can only be used with --decrypt")

    if args.salt and not args.encrypt:
        parser.error("--salt can only be used with --encrypt")

    file = Path(args.filename) # args.filename
    password = args.password or getpass.getpass("Enter password: ")

    if args.encrypt:
        output_file = args.output or f"encrypted-{file.name}"

        if args.salt:
            salt = bytes.fromhex(args.salt)
            if len(salt) != 8:
                parser.error("Salt must be exactly 8 bytes (16 hex characters) for OpenSSL compatibility.")
        else:
            salt = get_random_bytes(8)

        log.debug(f"Using salt: {salt.hex()}")

        try:
            with file.open("r", encoding="utf-8") as f:
                json_data = f.read().strip()
            # Validate JSON
            parsed = json.loads(json_data)
            formatted = json.dumps(parsed, separators=(',', ':'), sort_keys=True)
        except Exception as e:
            log.error(f"❌ Error reading or parsing JSON file '{file}': {e}")
            sys.exit(1)

        try:
            encrypted_b64 = encrypt_openssl_aes(formatted, password, salt)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(encrypted_b64)
            log.info(f"🔒 Encrypted file written to {output_file}")
        except Exception as e:
            log.error(f"❌ Encryption failed: {e}")
            sys.exit(1)

    else : # args.decrypt:
        output_file = args.output or f"decrypted-{file.name}"

        if args.extract_salt:
            extract_salt_from_file(file)

        try:
            with file.open("r", encoding="utf-8") as f:
                encrypted_text = f.read().strip()
        except Exception as e:
            log.error(f"❌ Error reading file '{file.name}': {e}")
            sys.exit(1)

        try:
            decrypted_bytes = decrypt_openssl_aes(encrypted_text, password)
            decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            log.error(f"❌ Decryption failed: {e}")
            sys.exit(1)

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(decrypted_text)
            log.info(f"✅ Decrypted content written to {output_file}")
        except Exception as e:
            log.error(f"❌ Error writing file '{output_file}': {e}")
            sys.exit(1)

        if args.export_pgp_keys:
            try:
                content = json.loads(decrypted_text)
                export_pgp_keys(content, output_file)
            except json.JSONDecodeError:
                log.error("❌ Decrypted content is not valid JSON; cannot extract PGP keys.")
            except Exception as e:
                log.error(f"❌️ Error exporting PGP keys: {e}")

if __name__ == "__main__":
    main()
    sys.exit(0)
