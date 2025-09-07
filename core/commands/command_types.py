#!/usr/bin/env python3
# core/commands/command_types.py
from __future__ import annotations

"""
Command data structures and protocols.

This module defines:
- CommandCallback: the callable protocol for any command implementation.
- CommandResult: a normalized, serializable result container for command outputs.
- Command: a registered command with metadata and a callable.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Callable


class CommandCallback(Protocol):
    """Protocol for any command function."""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - signature only
        ...


@dataclass(slots=True)
class CommandResult:
    """
    Normalized result container from command execution.

    Attributes:
        ok: True if the command completed successfully.
        message: Human-readable summary or primary output.
        data: Optional machine-readable payload (dict/list/primitive).
    """
    ok: bool = True
    message: str = ""
    data: Any = None

    def __str__(self) -> str:
        # Keep CLI printing predictable
        return self.message if self.message else ("ok" if self.ok else "error")


@dataclass(slots=True)
class Command:
    """
    A registered command with metadata and a callable to execute.

    Important fields:
        name: Primary unique command name.
        description: Short, user-facing description.
        example: One-line example usage string (optional).
        callback: Function implementing the command.
        id: Optional persistent identifier from the database.
        module: Python module path where the command is defined.
        category: Logical group for help menu organization.
        completers: Mapping for intelligent completions (positional and key=value).
        aliases: Extra names resolving to the same command.
        param_names: All parameter names discovered from the command signature.
    """

    name: str
    description: str
    example: str
    callback: CommandCallback
    id: int | None = None
    module: str = field(default="", repr=False)
    category: str = "general"
    completers: Mapping[str, Callable[..., object]] = field(     # type: ignore
        default_factory=dict)
    aliases: list[str] = field(default_factory=list)  # type: ignore
    param_names: list[str] = field(default_factory=list)  # type: ignore

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the underlying command callback with provided arguments."""
        return self.callback(*args, **kwargs)
