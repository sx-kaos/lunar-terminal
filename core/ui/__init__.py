#!/usr/bin/env python3
# core/ui/__init__.py
from __future__ import annotations
# Re-export convenient top-level API
from .utils import (
    ANSI,
    strip_ansi,
    enable_windows_vt,
    clear_screen,
    PRINT_MUTEX,
    print_line,
    set_terminal_title,
    get_terminal_columns,
    print_markup,
    colorize,
    rgb,
    render_markup,
    hex_color,
    hyperlink

)
from .static import (
    format_table,
    print_table,
    init_logger,
    ColorizingStreamHandler,
    PlainFormatter,
)
from .animated import ProgressBar, Spinner

__all__ = [
    "ANSI",
    "strip_ansi",
    "enable_windows_vt",
    "clear_screen",
    "colorize",
    "render_markup",
    "rgb",
    "hex_color",
    "hyperlink",
    "PRINT_MUTEX",
    "print_line",
    "print_markup",
    "set_terminal_title",
    "get_terminal_columns",
    "format_table",
    "print_table",
    "init_logger",
    "ColorizingStreamHandler",
    "PlainFormatter",
    "ProgressBar",
    "Spinner",
]
