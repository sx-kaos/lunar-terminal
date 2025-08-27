#!/usr/bin/env python3
# core/boot/__init__.py
from __future__ import annotations
"""
Boot sequence package.

Exports:
- boot_sequence: Orchestrated startup pipeline with Linux-style [ OK ] / [FAILED] lines.
- BootState: Dataclass containing workspace, logger, config, command count, and sysinfo.
"""


from .boot import BootState, boot_sequence

__all__ = ["boot_sequence", "BootState"]
