{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "decrypt-env";

  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.pycryptodome
  ];

  shellHook = ''
    echo "🔐 AES decryptor environment ready."
    echo "Usage: python decrypt.py <encryptedText> <password> [outputFile]"
  '';
}
