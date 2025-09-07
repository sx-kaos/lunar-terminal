#!/usr/bin/env python3
# core/ui/static/table.py
from __future__ import annotations

from typing import List, Optional, Sequence

from core.ui import strip_ansi
from core.ui import print_line


def _calculate_column_widths(rows: Sequence[Sequence[str]]) -> List[int]:
    """Compute visual widths ignoring ANSI sequences."""
    column_widths: List[int] = []
    for row in rows:
        for col_idx, cell in enumerate(row):
            cell_length = len(strip_ansi(str(cell)))
            if col_idx >= len(column_widths):
                column_widths.append(cell_length)
            else:
                column_widths[col_idx] = max(
                    column_widths[col_idx], cell_length)
    return column_widths


def format_table(
    rows: Sequence[Sequence[object]],
    headers: Optional[Sequence[object]] = None,
    *,
    padding: int = 1,
    border: bool = True,
) -> str:
    """Return an ASCII table string (ANSI-safe width calculation)."""
    str_rows: List[List[str]] = [[str(cell) for cell in row] for row in rows]

    if headers is not None:
        str_headers = [str(h) for h in headers]
        widths = _calculate_column_widths([str_headers] + str_rows)
    else:
        str_headers = None
        widths = _calculate_column_widths(str_rows)

    pad = " " * padding

    def render_row(row: Sequence[str]) -> str:
        parts = []
        for i, cell in enumerate(row):
            width = widths[i]
            right = " " * (width - len(strip_ansi(cell)))
            parts.append(f"{pad}{cell}{right}{pad}")
        return "|" + "|".join(parts) + "|"

    lines: List[str] = []
    if border:
        total = sum(widths) + (padding * 2 * len(widths)) + (len(widths) + 1)
        lines.append("-" * total)

    if headers is not None and str_headers is not None:
        lines.append(render_row(str_headers))
        lines.append(render_row(["-" * w for w in widths]))

    for row in str_rows:
        lines.append(render_row(row))

    if border:
        total = sum(widths) + (padding * 2 * len(widths)) + (len(widths) + 1)
        lines.append("-" * total)

    return "\n".join(lines)


def print_table(
    rows: Sequence[Sequence[object]],
    headers: Optional[Sequence[object]] = None,
    *,
    padding: int = 1,
    border: bool = True,
    file=None,
) -> None:
    """Print a formatted table to the given file."""
    text = format_table(rows, headers, padding=padding, border=border)
    if file is None:
        print_line(text)
    else:
        print_line(text, file=file)
