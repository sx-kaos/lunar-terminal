#!/usr/bin/env python3
# core/ui/utils/console.py
from __future__ import annotations

import ctypes
import os
import shutil
import sys
import threading

from .ansi import render_markup, enable_windows_vt  # NEW

# Single shared print mutex for all UI output (bars/spinners/logging).
PRINT_MUTEX = threading.Lock()


def print_line(text: str = "", *, file=sys.stdout, flush: bool = False) -> None:
    """Thread-safe single-line print that cooperates with spinners/bars."""
    with PRINT_MUTEX:
        file.write(f"{text}\n")
        if flush:
            file.flush()


def print_markup(text: str = "", *, file=sys.stdout, flush: bool = False) -> None:
    """Like print_line, but supports rich-like tags rendered to ANSI."""
    enable_windows_vt()
    with PRINT_MUTEX:
        file.write(render_markup(text) + "\n")
        if flush:
            file.flush()


def get_terminal_columns(default: int = 80) -> int:
    """Return current terminal column width with a sensible default."""
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default


def set_terminal_title(title_text: str) -> None:
    """Set the terminal window title with a Windows CMD-safe fallback."""
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(  # type: ignore[attr-defined]
                title_text
            )
        except Exception:
            os.system(f"title {title_text}")
    else:
        sys.stdout.write(f"\x1b]2;{title_text}\x07")
        sys.stdout.flush()
