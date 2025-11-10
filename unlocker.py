#!/usr/bin/env python3
"""
Unlocker
Peach GUI (PySide6) wrapper around unlocker_cli.py functions.

Requires: PySide6, and that unlocker-cli.py is importable in same folder
"""

import sys
import json
import traceback
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt

# Import functions from your unlocker_cli.py cli tool (must be in same directory)
# unlocker_cli.py must expose: encrypt_openssl_aes, decrypt_openssl_aes, extract_salt_from_file, export_pgp_keys
try:
    from unlocker_cli import (
        encrypt_openssl_aes,
        decrypt_openssl_aes,
        extract_salt_from_file,
        export_pgp_keys,
        get_version_info,
    )
except Exception as e:
    print("Failed to import functions from unlocker_cli.py:", e)
    print("Make sure unlocker.py and unlocker_cli.py are in the same folder and unlocker_cli.py exposes the functions.")
    raise

def show_error(parent, title, msg):
    QMessageBox.critical(parent, title, str(msg))

class PeachGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unlocker: Peach Backup — Encrypt / Decrypt")
        self.resize(400, 600)
        self.version_info = get_version_info()
        self._build_ui()
        self._build_status_bar()

    def _build_ui(self):
        v = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit()
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.on_browse)
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(btn_browse)
        v.addLayout(file_layout)

        # Mode selection (encrypt / decrypt)
        mode_layout = QHBoxLayout()
        self.decrypt_cb = QRadioButton("Decrypt")
        self.encrypt_cb = QRadioButton("Encrypt")
        # Ensure only one selected
        self.mode_group = QButtonGroup()
        self.mode_group.setExclusive(True)
        self.mode_group.addButton(self.decrypt_cb)
        self.mode_group.addButton(self.encrypt_cb)
        self.decrypt_cb.setChecked(True)
        mode_layout.addWidget(QLabel("Mode:"))
        mode_layout.addWidget(self.decrypt_cb)
        mode_layout.addWidget(self.encrypt_cb)
        v.addLayout(mode_layout)

        # Password input
        pass_layout = QHBoxLayout()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(QLabel("Password:"))
        pass_layout.addWidget(self.pass_edit)
        v.addLayout(pass_layout)

        # Output filename
        out_layout = QHBoxLayout()
        self.out_edit = QLineEdit()
        out_layout.addWidget(QLabel("Output:"))
        out_layout.addWidget(self.out_edit)
        v.addLayout(out_layout)

        # Salt field (optional)
        salt_layout = QHBoxLayout()
        self.salt_edit = QLineEdit()
        salt_layout.addWidget(QLabel("Salt (hex, 16 chars = 8 bytes) [optional]:"))
        salt_layout.addWidget(self.salt_edit)
        v.addLayout(salt_layout)

        # Options: extract salt, export pgp
        opt_layout = QHBoxLayout()
        self.extract_salt_cb = QCheckBox("Extract Salt (decrypt only)")
        self.export_pgp_cb = QCheckBox("Export PGP keys (decrypt only)")
        opt_layout.addWidget(self.extract_salt_cb)
        opt_layout.addWidget(self.export_pgp_cb)
        v.addLayout(opt_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self.on_run)
        self.open_out_btn = QPushButton("Open output")
        self.open_out_btn.clicked.connect(self.on_open_output)
        btn_layout.addWidget(self.run_btn)
        btn_layout.addWidget(self.open_out_btn)
        v.addLayout(btn_layout)

        # Log / output area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        v.addWidget(QLabel("Log / Output:"))
        v.addWidget(self.log_area)

        # Connect quick toggles
        self.decrypt_cb.toggled.connect(self.on_mode_change)
        self.on_mode_change(self.decrypt_cb.isChecked())

        # toggle salt checkbox on
        self.extract_salt_cb.setChecked(True)

        # Create a central widget and assign the layout
        central_widget = QWidget()
        central_widget.setLayout(v)
        self.setCentralWidget(central_widget)

    def _build_status_bar(self):
        # Create a label for the right-aligned message
        right_label = QLabel(f"{self.version_info['Name']} v{self.version_info['Version']} – {self.version_info['License']}")
        right_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        # Make it expand to take available space (pushes it to the right)
        right_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # Clear existing widgets and add the label
        status_bar = self.statusBar()  # built-in QMainWindow status bar
        status_bar.addPermanentWidget(right_label, 1)

    def on_browse(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select file")
        if fname:
            self.file_edit.setText(fname)
            # default output suggestions
            p = Path(fname)
            if self.decrypt_cb.isChecked():
                self.out_edit.setText(f"decrypted-{p.name}")
            else:
                self.out_edit.setText(f"encrypted-{p.name}")

    def on_mode_change(self, decrypt_mode):
        # enable/disable certain options
        self.extract_salt_cb.setEnabled(decrypt_mode)
        self.export_pgp_cb.setEnabled(decrypt_mode)
        if decrypt_mode:
            self.export_pgp_cb.setChecked(False)

    def append_log(self, *parts):
        self.log_area.append(" ".join(str(p) for p in parts))
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def on_open_output(self):
        out = self.out_edit.text().strip()
        if not out:
            show_error(self, "No output", "No output filename set")
            return
        p = Path(out)
        if not p.exists():
            show_error(self, "File missing", f"{out} does not exist")
            return
        # open with default program (platform)
        import subprocess, os
        if sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(p)], check=False)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(p)], check=False)
        elif sys.platform == "win32":
            os.startfile(str(p))

    def on_run(self):
        fname = self.file_edit.text().strip()
        if not fname:
            show_error(self, "No file", "Please choose a file first")
            return
        p = Path(fname)
        if not p.exists():
            show_error(self, "File not found", f"File not found: {fname}")
            return

        password = self.pass_edit.text()
        if not password:
            # prompt minimal dialog
            from PySide6.QtWidgets import QInputDialog
            ok = False
            password, ok = QInputDialog.getText(self, "Password", "Enter password:", QLineEdit.Password)
            if not ok or not password:
                self.append_log("Operation cancelled - no password provided")
                return
            else:
                self.pass_edit.setText(password)

        out_fname = self.out_edit.text().strip() or None
        salt_hex = self.salt_edit.text().strip() or None

        try:
            if self.decrypt_cb.isChecked():
                salt = None
                # Optionally extract salt first
                if self.extract_salt_cb.isChecked():
                    salt = extract_salt_from_file(p)
                    if salt:
                        salt_hex_value = salt.hex()
                        self.salt_edit.setText(salt_hex_value)
                        self.append_log(f"Extracted salt: {salt.hex()}")
                    else:
                        self.append_log("No salt found in file")

                # Read encrypted text
                encrypted_text = p.read_text(encoding="utf-8").strip()
                dec_bytes = decrypt_openssl_aes(encrypted_text, password)
                dec_text = dec_bytes.decode("utf-8", errors="replace")

                # write output
                if not out_fname:
                    out_fname = f"decrypted-{p.name}"
                Path(out_fname).write_text(dec_text, encoding="utf-8")
                self.append_log(f"Decrypted -> {out_fname}")

                # export pgp keys if requested
                if self.export_pgp_cb.isChecked():
                    try:
                        content = json.loads(dec_text)
                        export_pgp_keys(content, out_fname)
                        self.append_log("PGP export attempted")
                    except Exception as e:
                        self.append_log("PGP export failed:", e)

            else:
                # encrypt mode
                # read json file
                txt = p.read_text(encoding="utf-8").strip()
                parsed = json.loads(txt)  # validate
                formatted = json.dumps(parsed, separators=(',', ':'), sort_keys=True)
                salt = None
                if salt_hex:
                    salt = bytes.fromhex(salt_hex)
                    if len(salt) != 8:
                        raise ValueError("Salt must be 8 bytes (16 hex chars)")
                enc_b64 = encrypt_openssl_aes(formatted, password, salt)
                if not out_fname:
                    out_fname = f"encrypted-{p.name}"
                Path(out_fname).write_text(enc_b64, encoding="utf-8")
                self.append_log(f"Encrypted -> {out_fname} (salt: { (salt.hex() if salt else 'random') })")

        except Exception as e:
            show_error(self, "Operation failed", str(e))
            self.append_log(f"Error: {type(e).__name__}: {e}")
            traceback.print_exc()

def main():
    app = QApplication(sys.argv)
    gui = PeachGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
