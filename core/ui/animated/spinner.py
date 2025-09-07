#!/usr/bin/env python3
# core/ui/animated/spinner.py
from __future__ import annotations

import sys
import threading
import time

from core.ui import PRINT_MUTEX, get_terminal_columns


class Spinner:
    """A minimal CLI spinner context manager."""

    FRAMES = "|/-\\"

    def __init__(self, text: str = "Working...", *, file=sys.stderr, interval: float = 0.1) -> None:
        self.text = text
        self.file = file
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Spinner":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def stop(self) -> None:
        """Stop the spinner and clear the line."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join()
        cols = get_terminal_columns()
        with PRINT_MUTEX:
            self.file.write("\r" + " " * (cols - 1) + "\r")
            self.file.flush()

    def _run(self) -> None:
        frame_index = 0
        while not self._stop_event.is_set():
            frame = self.FRAMES[frame_index % len(self.FRAMES)]
            message = f"\r{frame} {self.text}"
            with PRINT_MUTEX:
                self.file.write(message)
                self.file.flush()
            time.sleep(self.interval)
            frame_index += 1
