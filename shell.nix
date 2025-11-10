{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "unlocker-env";

  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.pycryptodome
    pkgs.python3Packages.requests # HTTP / API
    pkgs.python3Packages.bech32 # address encoding
    pkgs.python3Packages.mnemonic # seed handling
    pkgs.python3Packages.cryptography # ecdsa
    pkgs.python3Packages.pyside6 # Qt6 bindings
    pkgs.fontconfig # needed for Qt
    #~ pkgs.python3Packages.rich # nicer / colored cli output
  ];

  shellHook = ''
    echo "Unlocker: 🔐 AES decryptor environment for peach bitcoin file backups ready."
    echo "             Including a graphical (GUI) wrapper for the script (CLI)."
    echo "Usage (GUI): python unlocker.py"
    echo "Usage (CLI): python unlocker_cli.py --help"
  '';
}
