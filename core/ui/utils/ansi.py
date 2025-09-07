#!/usr/bin/env python3
# core/ui/utils/ansi.py
from __future__ import annotations

import ctypes
import os
import re
from typing import Optional

# ---- Core SGR maps ----------------------------------------------------------

# Standard 8 colors + bright variants, foreground and background.
# Foreground: 30-37, Bright Foreground: 90-97
# Background: 40-47, Bright Background: 100-107
ANSI = {
    # reset
    "reset": "\x1b[0m",

    # styles
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "italic": "\x1b[3m",
    "underline": "\x1b[4m",
    "blink": "\x1b[5m",
    "reverse": "\x1b[7m",
    "hidden": "\x1b[8m",
    "strike": "\x1b[9m",

    # fg 8-color
    "black": "\x1b[30m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",

    # fg bright 8-color
    "bright_black": "\x1b[90m",
    "bright_red": "\x1b[91m",
    "bright_green": "\x1b[92m",
    "bright_yellow": "\x1b[93m",
    "bright_blue": "\x1b[94m",
    "bright_magenta": "\x1b[95m",
    "bright_cyan": "\x1b[96m",
    "bright_white": "\x1b[97m",

    # bg 8-color
    "bg_black": "\x1b[40m",
    "bg_red": "\x1b[41m",
    "bg_green": "\x1b[42m",
    "bg_yellow": "\x1b[43m",
    "bg_blue": "\x1b[44m",
    "bg_magenta": "\x1b[45m",
    "bg_cyan": "\x1b[46m",
    "bg_white": "\x1b[47m",

    # bg bright 8-color
    "bg_bright_black": "\x1b[100m",
    "bg_bright_red": "\x1b[101m",
    "bg_bright_green": "\x1b[102m",
    "bg_bright_yellow": "\x1b[103m",
    "bg_bright_blue": "\x1b[104m",
    "bg_bright_magenta": "\x1b[105m",
    "bg_bright_cyan": "\x1b[106m",
    "bg_bright_white": "\x1b[107m",
}

# Useful compiled regex
ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Rich-like markup tags: [red], [bg-blue], [bold], [/#RRGGBB], [/]
_TAG_RE = re.compile(
    r"\[(/?)([a-zA-Z_][\w-]*|#?[0-9A-Fa-f]{6}|rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\))\]")

_vt_enabled_cache: Optional[bool] = None  # cached across calls


# ---- Utilities --------------------------------------------------------------

def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return ANSI_REGEX.sub("", text)


def enable_windows_vt() -> bool:
    """
    Enable ANSI (VT) processing on Windows consoles when possible.
    Returns True if ANSI escapes should work on the current process.
    On non-Windows systems, always returns True.

    See: https://docs.python.org/3/library/os.html#os.name
    """
    global _vt_enabled_cache
    if _vt_enabled_cache is not None:
        return _vt_enabled_cache

    if os.name != "nt":
        _vt_enabled_cache = True
        return True

    # Terminals that already support ANSI
    if (
        os.environ.get("WT_SESSION")                  # Windows Terminal
        or os.environ.get("ANSICON")
        or os.environ.get("ConEmuANSI") == "ON"
        or os.environ.get("TERM", "").startswith(("xterm", "vt100"))
    ):
        _vt_enabled_cache = True
        return True

    # Try to enable VT on classic console
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        STD_OUTPUT_HANDLE = -11
        STD_ERROR_HANDLE = -12

        def try_enable(handle_id: int) -> bool:
            handle = kernel32.GetStdHandle(handle_id)
            if handle in (0, -1):
                return False
            mode = ctypes.c_uint()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            return bool(kernel32.SetConsoleMode(handle, new_mode))

        ok_out = try_enable(STD_OUTPUT_HANDLE)
        ok_err = try_enable(STD_ERROR_HANDLE)
        _vt_enabled_cache = bool(ok_out or ok_err)
    except Exception:
        _vt_enabled_cache = False

    return _vt_enabled_cache


def clear_screen() -> None:
    """Clear the terminal screen reliably on Windows and POSIX."""
    os.system("cls" if os.name == "nt" else "clear")


# ---- Low-level color builders ----------------------------------------------

def _sgr_truecolor_fg(r: int, g: int, b: int) -> str:
    return f"\x1b[38;2;{r};{g};{b}m"


def _sgr_truecolor_bg(r: int, g: int, b: int) -> str:
    return f"\x1b[48;2;{r};{g};{b}m"


def _parse_hex(rgb_hex: str) -> tuple[int, int, int]:
    r = int(rgb_hex[1:3], 16)
    g = int(rgb_hex[3:5], 16)
    b = int(rgb_hex[5:7], 16)
    return r, g, b


def rgb(r: int, g: int, b: int, *, background: bool = False) -> str:
    """Return a true-color SGR sequence for (r,g,b)."""
    r = max(0, min(255, r))
    g = max(0, min(255, g))
    b = max(0, min(255, b))
    return _sgr_truecolor_bg(r, g, b) if background else _sgr_truecolor_fg(r, g, b)


def hex_color(hex_code: str, *, background: bool = False) -> str:
    """Return a true-color SGR from '#RRGGBB'."""
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", hex_code):
        raise ValueError("hex_code must be like '#RRGGBB'.")
    r, g, b = _parse_hex(hex_code)
    return rgb(r, g, b, background=background)


def hyperlink(text: str, url: str) -> str:
    """
    OSC 8 hyperlink (supported by Windows Terminal, modern terminals).
    Falls back gracefully if not supported.
    """
    # \x1b]8;;<url>\x1b\\text\x1b]8;;\x1b\\
    return f"\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\"

# ---- High-level helpers -----------------------------------------------------


def colorize(text: str, *styles: str) -> str:
    """
    Wrap text with one or more SGR styles/keys from ANSI (e.g., 'red', 'bold', 'bg_blue').
    Always auto-resets at the end.
    """
    seq = "".join(ANSI[s] for s in styles if s in ANSI)
    return f"{seq}{text}{ANSI['reset']}" if seq else text


# ---- Rich-like markup renderer ---------------------------------------------

# Supported tags:
#   [red]...[/red], [bg-blue]...[/bg-blue], [bold]...[/bold], [underline]...[/underline]
#   [#RRGGBB]...[/#RRGGBB] foreground true-color
#   [rgb(R,G,B)]...[/rgb(R,G,B)] foreground true-color
#   Reset with closing tag or universal [/]
#
# Example:
#   render_markup("Normal [red]red [bold]bold red[/bold][/red] normal")
#
# Rules:
# - Tags must be well-nested (simple stack).
# - Unknown tags are passed through literally.
# - On any closing tag, emit ANSI['reset'] then re-emit remaining stack styles.

def render_markup(text: str) -> str:
    enable_windows_vt()  # best effort

    out: list[str] = []
    stack: list[str] = []         # holds ANSI sequences for active styles
    stack_keys: list[str] = []    # human-readable keys to match closers

    i = 0
    for m in _TAG_RE.finditer(text):
        start, end = m.span()
        out.append(text[i:start])  # plain text up to tag
        is_close = bool(m.group(1))
        tag = m.group(2)
        i = end

        if not is_close:
            # opening tag
            try:
                if tag in ANSI:
                    seq = ANSI[tag]
                    stack.append(seq)
                    stack_keys.append(tag)
                    out.append(seq)
                elif tag.startswith("bg-") and ("bg_" + tag[3:]) in ANSI:
                    k = "bg_" + tag[3:]
                    seq = ANSI[k]
                    stack.append(seq)
                    stack_keys.append(k)
                    out.append(seq)
                elif re.fullmatch(r"#[0-9A-Fa-f]{6}", tag):
                    seq = hex_color(tag)
                    stack.append(seq)
                    stack_keys.append(tag)
                    out.append(seq)
                elif tag.lower().startswith("rgb("):
                    nums = re.findall(r"\d+", tag)
                    if len(nums) == 3:
                        r, g, b = (int(nums[0]), int(nums[1]), int(nums[2]))
                        seq = rgb(r, g, b)
                        stack.append(seq)
                        stack_keys.append(tag.lower())
                        out.append(seq)
                    else:
                        out.append("[" + tag + "]")  # invalid -> literal
                else:
                    out.append("[" + tag + "]")      # unknown -> literal
            except Exception:
                out.append("[" + tag + "]")
        else:
            # closing tag
            if tag == "":  # never occurs (kept for completeness)
                continue

            # universal close [/]
            if tag == "/":
                stack.clear()
                stack_keys.clear()
                out.append(ANSI["reset"])
                continue

            # Try to close matching top or search
            key = tag
            if tag.startswith("bg-"):
                key = "bg_" + tag[3:]
            key = key if key in ANSI or key.startswith(
                "#") or key.startswith("rgb(") else tag

            if key in stack_keys:
                # pop until key
                while stack_keys:
                    popped_key = stack_keys.pop()
                    stack.pop()
                    if popped_key == key:
                        break
                # reset then re-emit active styles
                out.append(ANSI["reset"])
                if stack:
                    out.append("".join(stack))
            else:
                # unknown closer -> literal
                out.append("[/" + tag + "]")

    out.append(text[i:])  # remainder
    if stack:
        out.append(ANSI["reset"])
    return "".join(out)
