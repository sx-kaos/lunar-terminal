#!/usr/bin/env python3
# core/commands/__init__.py
from __future__ import annotations

"""
Package for command management and registration.

Provides:
- Data structures and protocols (`Command`, `CommandResult`, `CommandCallback`).
- In-memory registry and decorators (`REGISTRY`, `command`, `register_command`).
- Dynamic loader for discovering command modules (`load_commands`).

This package re-exports public APIs from:
- command_types.py
- commands.py
"""


# Re-export from submodules
from .command_types import Command, CommandResult, CommandCallback
from .commands import REGISTRY, command, register_command

__all__ = [
    "Command",
    "CommandResult",
    "CommandCallback",
    "REGISTRY",
    "command",
    "register_command",
]
