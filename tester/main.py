import sys, os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QRadioButton, QTextEdit, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, QTimer
from PyQt6.QtGui import QIcon
from password_worker import PasswordWorker


class PasswordTester(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Tester")
        self.setGeometry(200, 200, 800, 350)
        self.setWindowIcon(QIcon("tester/mc10.PNG"))

        # ========== UI FOUNDATION ==========
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

        # ==== Left side (inputs) ====
        left_layout = QVBoxLayout()

        self.label = QLabel("Enter your password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(
            "border: 1px solid gray; padding: 4px; font-size: 12px; color: black;"
        )

        self.mode_label = QLabel("Select Attack Mode:")
        self.dict_mode = QRadioButton("Dictionary Attack")
        self.brute_mode = QRadioButton("Brute-Force Attack")
        self.dict_mode.setChecked(True)

        mode_layout = QHBoxLayout()
        mode_layout.addWidget(self.dict_mode)
        mode_layout.addWidget(self.brute_mode)

        self.check_button = QPushButton("Check Password")
        self.check_button.setStyleSheet(
            """
            QPushButton {
                background-image: url('mc10.PNG');
                background-repeat: no-repeat;
                background-position: center;
                min-width: 128px;
                min-height: 64px;
            }
            QPushButton:hover {
                background-color: #C0C0C0;
            }
            """
        )

        self.cinematic_checkbox = QCheckBox("Cinematic mode (slow scroll)")
        self.cinematic_checkbox.setChecked(False)

        self.result_label = QLabel("")
        self.result_label.setStyleSheet("font-weight: bold; margin-top: 8px; color: black;")

        left_layout.addWidget(self.label)
        left_layout.addWidget(self.password_input)
        left_layout.addWidget(self.mode_label)
        left_layout.addLayout(mode_layout)
        left_layout.addWidget(self.check_button)
        left_layout.addWidget(self.cinematic_checkbox)
        left_layout.addWidget(self.result_label)
        left_layout.addStretch()

        # ==== Right side (console) ====
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "background-color: black; color: lime; font-family: Consolas; font-size: 11px;"
        )
        self.console.setText("Password Tester Console Initialized...\n")

        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.console, 2)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Wordlists setup
        self.wordlists_dir = os.path.join(os.path.dirname(__file__), "wordlists")

        # Connect
        self.check_button.clicked.connect(self.start_check)

    # ======================================================
    # Control Flow
    # ======================================================
    def start_check(self):
        self.password = self.password_input.text().strip()
        self.wordlists = [
            os.path.join(self.wordlists_dir, f)
            for f in os.listdir(self.wordlists_dir)
            if os.path.isfile(os.path.join(self.wordlists_dir, f))
        ]
        self.current_idx = 0
        self.console.append(f"\n=== Starting scan for: '{self.password}' ===")
        self.result_label.setText("Scanning...")
        self.lists_total = 0
        self.matches_total = 0  # track across all lists
        self.start_next_wordlist()

    def start_next_wordlist(self):
        if self.current_idx >= len(self.wordlists):
            # finished all
            if self.matches_total > 0:
                self.console.append(f"\n=== Scan finished. Matches found in {self.matches_total}/{self.lists_total} lists. ===")
                self.result_label.setText(f"❌ Weak password (found in {self.matches_total}/{self.lists_total} lists).")
            else:
                self.console.append("\n=== Scan finished. No matches found. ===")
                self.result_label.setText("✅ Not found in any wordlist.")
            return

        path = self.wordlists[self.current_idx]
        delay = 0.001 if self.cinematic_checkbox.isChecked() else 0.0
        cinematic = self.cinematic_checkbox.isChecked()

        self.console.append(f"\n--- Checking {os.path.basename(path)} ---")

        self.thread = QThread()
        self.worker = PasswordWorker(self.password, path, delay=delay, cinematic=cinematic)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.console.append)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_worker_finished(self, filename, found, line_number, elapsed):
        if found:
            self.console.append(
                f"\n*** Match found in {filename}, line {line_number} (time {elapsed:.2f}s)."
            )
            self.matches_total += 1
            self.result_label.setText(f"❌ Weak: found in {filename}")
        else:
            self.console.append(f"Completed {filename} with no match. (time {elapsed:.2f}s)")

        # Move to next wordlist after 5s pause
        self.current_idx += 1
        self.lists_total += 1
        QTimer.singleShot(3000, self.start_next_wordlist)


def main():
    app = QApplication(sys.argv)
    window = PasswordTester()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()