#!/usr/bin/env python3
# core/ui/animated/progress.py
from __future__ import annotations

import sys
import threading
import time

from core.ui import PRINT_MUTEX, get_terminal_columns


class ProgressBar:
    """
    A simple, TTY-aware progress bar with ETA and rate.

    Usage:
        with ProgressBar(total_units=10, label_text="Scanning") as bar:
            bar.increment()
    """

    def __init__(self, total_units: int, *, label_text: str = "", file=sys.stderr) -> None:
        self.total_units = max(1, int(total_units))
        self.completed_units = 0
        self.label_text = label_text
        self.file = file
        self.start_time = time.time()
        self._last_render_at = 0.0
        self._mutex = threading.Lock()
        self._closed = False
        self._render(force=True)

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def update(self, new_value: int) -> None:
        """Set absolute completed units."""
        with self._mutex:
            self.completed_units = max(0, min(self.total_units, new_value))
            self._render()

    def increment(self, step: int = 1) -> None:
        """Increase completed units by a step."""
        with self._mutex:
            self.completed_units = max(
                0, min(self.total_units, self.completed_units + step)
            )
            self._render()

    # ---- internals ---------------------------------------------------------

    def _format_eta_and_rate(self) -> str:
        elapsed = time.time() - self.start_time
        rate = self.completed_units / elapsed if elapsed > 0 else 0.0
        remaining = (
            (self.total_units - self.completed_units) / rate if rate > 0 else 0.0
        )

        def fmt(seconds: float) -> str:
            minutes, secs = divmod(int(seconds), 60)
            hours, minutes = divmod(minutes, 60)
            if hours:
                return f"{hours:d}h{minutes:02d}m"
            if minutes:
                return f"{minutes:d}m{secs:02d}s"
            return f"{secs:d}s"

        return f"{fmt(remaining)} ETA | {rate:.1f}/s"

    def _render(self, *, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_render_at) < 0.05:
            return
        self._last_render_at = now

        terminal_width = get_terminal_columns()
        progress_ratio = self.completed_units / self.total_units
        bar_width = max(10, min(40, terminal_width // 4))
        filled_width = int(bar_width * progress_ratio)
        bar = "[" + "#" * filled_width + "-" * (bar_width - filled_width) + "]"
        percent_text = f"{int(progress_ratio * 100):3d}%"
        eta_text = self._format_eta_and_rate()
        prefix = f"{self.label_text} " if self.label_text else ""
        line = (
            f"\r{prefix}{bar} {percent_text}  "
            f"{self.completed_units}/{self.total_units}  {eta_text}"
        )

        with PRINT_MUTEX:
            self.file.write(line[: terminal_width - 1])
            self.file.flush()

        if self.completed_units >= self.total_units:
            self.close()

    def close(self) -> None:
        """Erase bar and finalize output line."""
        if self._closed:
            return
        self._closed = True
        cols = get_terminal_columns()
        with PRINT_MUTEX:
            self.file.write("\r" + " " * (cols - 1) + "\r")
            self.file.flush()
