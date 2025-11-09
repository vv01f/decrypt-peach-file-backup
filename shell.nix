{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "decrypt-env";

  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.pycryptodome
    #~ pkgs.python3Packages.requests # HTTP / API
    #~ pkgs.python3Packages.rich # nicer / colored cli output
  ];

  shellHook = ''
    echo "🔐 AES decryptor environment ready."
    echo "Usage: python decrypt.py --help"
  '';
}
