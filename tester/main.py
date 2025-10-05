import sys, os, time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QRadioButton, QTextEdit, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, QTimer
from PyQt6.QtGui import QIcon
from password_worker import PasswordWorker


# ======================================================
# Brute-force math estimator
# ======================================================
def brute_force_exact(password: str, charset: str, guesses_per_second=100_000):
    """
    Estimate the total number of attempts and time required to brute-force
    a specific password using a given charset and guess rate.
    """
    N = len(charset)
    L = len(password)

    # Total attempts before reaching passwords of the same length
    attempts_before = sum(N**i for i in range(1, L))

    # Compute rank of given password within its length-space
    rank = 0
    for c in password:
        idx = charset.find(c)
        if idx == -1:
            raise ValueError(f"Character '{c}' not in charset")
        rank = rank * N + idx

    # Total attempts = attempts of shorter lengths + rank position + 1
    total_attempts = attempts_before + rank + 1
    seconds = total_attempts / guesses_per_second
    return total_attempts, seconds, N, L


# Default charset: lowercase, uppercase, digits, symbols, and space
DEFAULT_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~ "
)


# ======================================================
# Main GUI class
# ======================================================
class PasswordTester(QMainWindow):
    """
    Main window for the Password Tester application.
    Allows the user to perform dictionary or brute-force
    password vulnerability checks.
    """

    def __init__(self):
        super().__init__()

        # ---- Window setup ----
        self.setWindowTitle("Password Tester")
        self.setGeometry(200, 200, 800, 350)
        self.setWindowIcon(QIcon("tester/mc10.PNG"))

        # ---- State variables ----
        self.scanning = False
        self.thread = None
        self.worker = None

        # ---- UI setup ----
        central_widget = QWidget()
        central_widget.setStyleSheet(
            """
            QWidget { background-color: white; }
            QLabel, QRadioButton, QPushButton, QCheckBox { color: black; font-size: 12px; }
            QCheckBox::indicator { background: white; border: 1px solid black; }
            QCheckBox::indicator:checked { background-color: #0078D7; border: 1px solid black; }
            """
        )
        main_layout = QHBoxLayout()

        # ---- Left panel ----
        left_layout = QVBoxLayout()

        self.label = QLabel("Enter your password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.password_input.setStyleSheet(
            "border: 1px solid gray; padding: 4px; font-size: 12px; color: black;"
        )

        # ---- Attack mode selection ----
        self.mode_label = QLabel("Select Attack Mode:")
        self.dict_mode = QRadioButton("Dictionary Attack")
        self.dict_mode.setStyleSheet(
            """
            QRadioButton::indicator {
                border: 1px solid #606060;
                background-color: #E0E0E0;
                width: 12px;
                height: 12px;
                border-radius: 7px;
            }
            QRadioButton::indicator:checked {
                background-color: #a2db66;
                border: 1px solid #000000;
            }
            """
        )
        self.brute_mode = QRadioButton("Brute-Force Attack")
        self.brute_mode.setStyleSheet(
            """
            QRadioButton::indicator {
                border: 1px solid #606060;
                background-color: #E0E0E0;
                width: 12px;
                height: 12px;
                border-radius: 7px;
            }
            QRadioButton::indicator:checked {
                background-color: #a2db66;
                border: 1px solid #000000;
            }
            """
        )
        self.dict_mode.setChecked(True)

        mode_layout = QHBoxLayout()
        mode_layout.addWidget(self.dict_mode)
        mode_layout.addWidget(self.brute_mode)

        # ---- Check button ----
        self.check_button = QPushButton("Check Password")
        self.check_button.setStyleSheet(
            """
            QPushButton {
                color: white;
                background-image: url('tester/mc10.PNG');
                background-repeat: no-repeat;
                background-position: center;
                min-width: 128px;
                min-height: 64px;
            }
            QPushButton:hover { background-color: #C0C0C0; }
            """
        )

        # ---- Cinematic mode ----
        self.cinematic_checkbox = QCheckBox("Cinematic mode (slow scroll)")
        self.cinematic_checkbox.setChecked(False)

        self.result_label = QLabel("")
        self.result_label.setStyleSheet("font-weight: bold; margin-top: 8px; color: black;")

        # Assemble left layout
        left_layout.addWidget(self.label)
        left_layout.addWidget(self.password_input)
        left_layout.addWidget(self.mode_label)
        left_layout.addLayout(mode_layout)
        left_layout.addWidget(self.check_button)
        left_layout.addWidget(self.cinematic_checkbox)
        left_layout.addWidget(self.result_label)
        left_layout.addStretch()

        # ---- Console panel ----
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "background-color: black; color: lime; font-family: Consolas; font-size: 11px;"
        )
        self.console.setText("Password Tester Console Initialized...\n")

        # Add panels to main layout
        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.console, 2)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Set location for wordlists
        self.wordlists_dir = os.path.join(os.path.dirname(__file__), "wordlists")

        # Connect button to toggle between Start / Abort
        self.check_button.clicked.connect(self.on_check_clicked)

    # ======================================================
    # Button click handling (Start / Abort toggle)
    # ======================================================
    def on_check_clicked(self):
        """Decide whether to start or abort the current scan."""
        if not self.scanning:
            self.start_check()
        else:
            self.abort_scan()

    # ======================================================
    # Start password check (dictionary or brute-force)
    # ======================================================
    def start_check(self):
        """Initialize scanning process based on selected attack mode."""
        self.password = self.password_input.text().strip()
        self.console.clear()
        self.scanning = True
        self.check_button.setText("Abort")

        # ---- Dictionary attack mode ----
        if self.dict_mode.isChecked():
            self.wordlists = [
                os.path.join(self.wordlists_dir, f)
                for f in os.listdir(self.wordlists_dir)
                if os.path.isfile(os.path.join(self.wordlists_dir, f))
            ]
            self.current_idx = 0
            self.console.append(f"=== Starting dictionary scan for: '{self.password}' ===")
            self.result_label.setText("Scanning...")
            self.lists_total = 0
            self.matches_total = 0
            self.start_next_wordlist()

        # ---- Brute-force simulation mode ----
        elif self.brute_mode.isChecked():
            self.console.append(f"=== Starting brute-force simulation for: '{self.password}' ===")
            try:
                # Perform estimation only; no actual cracking occurs
                attempts, seconds, N, L = brute_force_exact(self.password, DEFAULT_CHARSET)
                self.console.append(f"Charset size: {N}")
                self.console.append(f"Password length: {L}")
                self.console.append(f"Total attempts needed: {attempts:,}")

                # Convert time into human-readable format
                years, remainder = divmod(seconds, 31536000)
                days, remainder = divmod(remainder, 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, seconds = divmod(remainder, 60)

                self.console.append(
                    f"Expected crack time @100k/s: {int(years)}y {int(days)}d "
                    f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                )
                self.result_label.setText("Brute-force time estimation complete.")

            except ValueError as e:
                self.console.append(f"Error: {e}")

            # Reset state after estimation
            self.scanning = False
            self.check_button.setText("Check Password")

    # ======================================================
    # Abort active scan
    # ======================================================
    def abort_scan(self):
        """Abort any ongoing dictionary scan."""
        self.console.append("\n=== Aborting current scan... ===")
        self.scanning = False
        self.check_button.setText("Check Password")

        try:
            if self.worker and hasattr(self.worker, "stop"):
                self.worker.stop()
            if self.thread and self.thread.isRunning():
                self.thread.quit()
        except Exception:
            pass

        self.result_label.setText("Scan aborted by user.")

    # ======================================================
    # Sequentially process each wordlist in separate threads
    # ======================================================
    def start_next_wordlist(self):
        """Launch scanning for the next wordlist file."""
        if not self.scanning:
            return

        # All wordlists completed
        if self.current_idx >= len(self.wordlists):
            if self.matches_total > 0:
                self.console.append(
                    f"\n=== Scan finished. Matches found in {self.matches_total}/{self.lists_total} lists. ==="
                )
                self.result_label.setText(
                    f"❌ Weak password (found in {self.matches_total}/{self.lists_total} lists)."
                )
            else:
                self.console.append("\n=== Scan finished. No matches found. ===")
                self.result_label.setText("✅ Not found in any wordlist.")

            self.scanning = False
            self.check_button.setText("Check Password")
            return

        # Prepare next dictionary file
        path = self.wordlists[self.current_idx]
        delay = 0.001 if self.cinematic_checkbox.isChecked() else 0.0
        cinematic = self.cinematic_checkbox.isChecked()

        self.console.append(f"\n--- Checking {os.path.basename(path)} ---")

        # Worker-thread setup
        self.thread = QThread()
        self.worker = PasswordWorker(self.password, path, delay=delay, cinematic=cinematic)
        self.worker.moveToThread(self.thread)

        # Signal-slot connections
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.console.append)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # Start next file processing
        self.thread.start()

    # ======================================================
    # Worker finished callback
    # ======================================================
    def on_worker_finished(self, filename, found, line_number, elapsed):
        """Handle results after worker completes a wordlist scan."""
        if not self.scanning:
            return

        # Report status
        if found:
            self.console.append(
                f"\n*** Match found in {filename}, line {line_number} (time {elapsed:.2f}s)."
            )
            self.matches_total += 1
        else:
            self.console.append(f"Completed {filename} with no match. (time {elapsed:.2f}s)")

        self.current_idx += 1
        self.lists_total += 1

        # Delay before starting next list
        QTimer.singleShot(3000, self.start_next_wordlist)


# ======================================================
# Application entry point
# ======================================================
def main():
    """Application entry point."""
    app = QApplication(sys.argv)
    window = PasswordTester()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()