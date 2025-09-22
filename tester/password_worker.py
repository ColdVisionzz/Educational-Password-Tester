from PyQt6.QtCore import QObject, pyqtSignal
import os, time

class PasswordWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, bool, int, float)
    # emits (filename, found, line_number, elapsed)

    def __init__(self, password: str, wordlist_path: str,
                 delay: float = 0.0, cinematic: bool = False):
        super().__init__()
        self.password = password.strip()
        self.wordlist_path = wordlist_path
        self.delay = delay
        self.cinematic = cinematic
        self._is_running = True

    def run(self):
        start_time = time.perf_counter()
        found, line_number = False, None

        try:
            # Lazy approach: do not pre-count unless needed
            total_lines = None
            if not self.cinematic:
                # figure out how big list is for throttling logic
                with open(self.wordlist_path, encoding="utf-8", errors="ignore") as f:
                    total_lines = sum(1 for _ in f)

            with open(self.wordlist_path, encoding="utf-8", errors="ignore") as f:
                for lineno, word in enumerate(f, start=1):
                    if not self._is_running:
                        break

                    candidate = word.strip()
                    is_match = (self.password == candidate)

                    if self.cinematic or (total_lines and total_lines <= 50000):
                        msg = f'{os.path.basename(self.wordlist_path)} Line {lineno} "{candidate}" - '
                        msg += "MATCH!" if is_match else "NO MATCH"
                        self.progress.emit(msg)
                        if self.delay > 0:
                            time.sleep(self.delay)
                    else:
                        if is_match:
                            self.progress.emit(
                                f'{os.path.basename(self.wordlist_path)} Line {lineno} "{candidate}" - MATCH!'
                            )
                        elif lineno % 1000 == 0:
                            self.progress.emit(
                                f"{os.path.basename(self.wordlist_path)} Line {lineno} ... still scanning"
                            )

                    if is_match:
                        found, line_number = True, lineno
                        break  # STOP scanning this wordlist after first match!

        except FileNotFoundError:
            self.progress.emit(f"ERROR: Wordlist not found: {self.wordlist_path}")

        elapsed = time.perf_counter() - start_time
        self.finished.emit(os.path.basename(self.wordlist_path), found, line_number, elapsed)

    def stop(self):
        self._is_running = False