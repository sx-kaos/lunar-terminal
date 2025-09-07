#!/usr/bin/env python3
# core/ui/static/__init__.py
from __future__ import annotations
from .table import format_table, print_table
from .logging import (
    init_logger,
    ColorizingStreamHandler,
    PlainFormatter,
)

__all__ = [
    "format_table",
    "print_table",
    "init_logger",
    "ColorizingStreamHandler",
    "PlainFormatter",
]
