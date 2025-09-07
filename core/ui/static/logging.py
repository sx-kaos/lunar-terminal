#!/usr/bin/env python3
# core/ui/static/logging.py
from __future__ import annotations

import ctypes
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple

from core.ui import ANSI, enable_windows_vt, strip_ansi
from core.ui import PRINT_MUTEX


class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _SMALL_RECT(ctypes.Structure):
    _fields_ = [
        ("Left", ctypes.c_short),
        ("Top", ctypes.c_short),
        ("Right", ctypes.c_short),
        ("Bottom", ctypes.c_short),
    ]


class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", _COORD),
        ("dwCursorPosition", _COORD),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", _SMALL_RECT),
        ("dwMaximumWindowSize", _COORD),
    ]


class ColorizingStreamHandler(logging.StreamHandler):
    """
    StreamHandler with ANSI → WinAPI → plain fallback.
    """
    _HAS_WINDOWS = os.name == "nt"
    _FOREGROUND_BLUE = 0x0001
    _FOREGROUND_GREEN = 0x0002
    _FOREGROUND_RED = 0x0004
    _FOREGROUND_INTENSITY = 0x0008

    _LEVEL_COLORS = {
        logging.DEBUG: (ANSI["bright_black"], _FOREGROUND_INTENSITY),
        logging.INFO: ("", _FOREGROUND_RED | _FOREGROUND_GREEN | _FOREGROUND_BLUE),
        logging.WARNING: (ANSI["yellow"], _FOREGROUND_RED | _FOREGROUND_GREEN | _FOREGROUND_INTENSITY),
        logging.ERROR: (ANSI["red"], _FOREGROUND_RED | _FOREGROUND_INTENSITY),
        logging.CRITICAL: (ANSI["magenta"], _FOREGROUND_RED | _FOREGROUND_BLUE | _FOREGROUND_INTENSITY),
    }

    def __init__(self, stream=None) -> None:
        super().__init__(stream)
        self._use_ansi = enable_windows_vt()
        self._win_handles: Optional[Tuple[object, int, int]] = None

        if self._HAS_WINDOWS and not self._use_ansi:
            try:
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                STD_OUTPUT_HANDLE = -11
                STD_ERROR_HANDLE = -12
                is_stdout = self.stream in (sys.stdout, sys.__stdout__)
                std_id = STD_OUTPUT_HANDLE if is_stdout else STD_ERROR_HANDLE
                handle = kernel32.GetStdHandle(std_id)
                csbi = self._get_csbi(handle)
                self._win_handles = (kernel32, handle, csbi.wAttributes)
            except Exception:
                self._win_handles = None

    def _get_csbi(self, handle):
        csbi = _CONSOLE_SCREEN_BUFFER_INFO()
        ctypes.windll.kernel32.GetConsoleScreenBufferInfo(  # type: ignore[attr-defined]
            handle, ctypes.byref(csbi)
        )
        return csbi

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)

            if self._use_ansi:
                ansi, _ = self._LEVEL_COLORS.get(record.levelno, ("", None))
                if ansi:
                    message = f"{ansi}{message}{ANSI['reset']}"
                with PRINT_MUTEX:
                    self.stream.write(message + self.terminator)
                    self.flush()
                return

            if self._win_handles:
                kernel32, handle, default_attr = self._win_handles
                _, attr = self._LEVEL_COLORS.get(
                    record.levelno, ("", default_attr))
                with PRINT_MUTEX:
                    try:
                        kernel32.SetConsoleTextAttribute(  # type: ignore
                            handle, attr)
                        self.stream.write(strip_ansi(
                            message) + self.terminator)
                    finally:
                        kernel32.SetConsoleTextAttribute(  # type: ignore
                            handle, default_attr)
                    self.flush()
                return

            with PRINT_MUTEX:
                self.stream.write(strip_ansi(message) + self.terminator)
                self.flush()
        except Exception:
            self.handleError(record)


class PlainFormatter(logging.Formatter):
    """Formatter that strips ANSI (good for log files)."""

    def format(self, record: logging.LogRecord) -> str:
        record.msg = strip_ansi(str(record.msg))
        return super().format(record)


def init_logger(
    name: str = "",
    level: int = logging.INFO,
    logfile: Optional[str] = None,
) -> logging.Logger:
    """
    Initialize a color-safe logger.

    Console: ANSI if available, else WinAPI, else plain.
    File (optional): rotating, plain text, UTF-8.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not any(isinstance(h, ColorizingStreamHandler) for h in logger.handlers):
        console_handler = ColorizingStreamHandler(stream=sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(
            logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(console_handler)

    if logfile and not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        file_handler = RotatingFileHandler(
            logfile, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            PlainFormatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)

    return logger
