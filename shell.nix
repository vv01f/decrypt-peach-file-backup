{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "unlocker-env";

  buildInputs = with pkgs; [
    python3
    python3Packages.pycryptodome
    python3Packages.requests # HTTP / API
    python3Packages.bech32 # address encoding
    python3Packages.mnemonic # seed handling
    python3Packages.cryptography # ecdsa
    python3Packages.pyside6 # Qt6 bindings
    #~ qt6.full
    pkgs.qt6.qtbase
    fontconfig # needed for Qt
    qt6.wrapQtAppsHook # fix fontconfig warning
    #~ python3Packages.rich # nicer / colored cli output
  ];

  shellHook = ''
    export QT_QPA_PLATFORM_PLUGIN_PATH=${pkgs.qt6.qtbase}/lib/qt-6/plugins/platforms
    export FONTCONFIG_FILE=${pkgs.fontconfig.out}/etc/fonts/fonts.conf
    export FONTCONFIG_PATH=${pkgs.fontconfig.out}/etc/fonts
    export XDG_DATA_DIRS=${pkgs.qt6.qtbase}/share:${pkgs.qt6.qtwayland}/share:$XDG_DATA_DIRS
    export QT_LOGGING_RULES="*.debug=false;qt.qpa.fonts.warning=false" # silence fontconfig warning
    echo "Unlocker: 🔐 AES decryptor environment for peach bitcoin file backups ready."
    echo "             Including a graphical (GUI) wrapper for the script (CLI)."
    echo "Usage (GUI): python unlocker.py"
    echo "Usage (CLI): python unlocker_cli.py --help"
  '';
}
