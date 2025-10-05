from PyQt6.QtCore import QObject, pyqtSignal
import os, time


class PasswordWorker(QObject):
    """
    Worker class responsible for scanning a given wordlist file.
    Runs in a separate thread to prevent blocking the GUI.
    """

    # ---- Signals ----
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, bool, int, float)
    # Emits:
    #   (filename, found, line_number, elapsed_time)

    def __init__(
        self,
        password: str,
        wordlist_path: str,
        delay: float = 0.0,
        cinematic: bool = False,
    ):
        """
        Initialize worker with password target and wordlist source.

        Args:
            password: The target password to search for.
            wordlist_path: Path to the wordlist file.
            delay: Optional delay for cinematic output mode.
            cinematic: Whether to show every attempted word.
        """
        super().__init__()
        self.password = password.strip()
        self.wordlist_path = wordlist_path
        self.delay = delay
        self.cinematic = cinematic
        self._is_running = True  # Internal flag for abortion control

    def run(self):
        """
        Primary execution method for wordlist scanning.

        Reads the given wordlist line-by-line, compares against the
        provided password, and emits progress messages along the way.
        """
        start_time = time.perf_counter()
        found, line_number = False, None

        try:
            # Optionally pre-count total lines (used for throttling behavior)
            total_lines = None
            if not self.cinematic:
                with open(self.wordlist_path, encoding="utf-8", errors="ignore") as f:
                    total_lines = sum(1 for _ in f)

            # Begin reading and matching process
            with open(self.wordlist_path, encoding="utf-8", errors="ignore") as f:
                for lineno, word in enumerate(f, start=1):
                    if not self._is_running:
                        break  # Early exit if scan aborted

                    candidate = word.strip()
                    is_match = self.password == candidate

                    # ---- Cinematic / full output mode ----
                    if self.cinematic or (total_lines and total_lines <= 50000):
                        msg = (
                            f'{os.path.basename(self.wordlist_path)} '
                            f'Line {lineno} "{candidate}" - '
                        )
                        msg += "MATCH!" if is_match else "NO MATCH"
                        self.progress.emit(msg)

                        # Optional delay for visual pacing
                        if self.delay > 0:
                            time.sleep(self.delay)

                    # ---- Condensed output mode ----
                    else:
                        if is_match:
                            self.progress.emit(
                                f'{os.path.basename(self.wordlist_path)} '
                                f'Line {lineno} "{candidate}" - MATCH!'
                            )
                        elif lineno % 1000 == 0:
                            # Emit periodic status every 1000 lines
                            self.progress.emit(
                                f"{os.path.basename(self.wordlist_path)} "
                                f"Line {lineno} ... still scanning"
                            )

                    # If a match is found, stop scanning this list
                    if is_match:
                        found, line_number = True, lineno
                        break

        except FileNotFoundError:
            # Handle missing file gracefully
            self.progress.emit(f"ERROR: Wordlist not found: {self.wordlist_path}")

        # ---- Emit completion signal ----
        elapsed = time.perf_counter() - start_time
        self.finished.emit(
            os.path.basename(self.wordlist_path),
            found,
            line_number,
            elapsed,
        )

    def stop(self):
        """Safely request early termination of the worker loop."""
        self._is_running = False