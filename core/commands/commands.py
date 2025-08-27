#!/usr/bin/env python3
# core/commands/commands.py
from __future__ import annotations

"""
Command registry and decorator utilities.

This module provides:
- CommandRegistry: in-memory registry of commands and aliases.
- command: decorator to register functions as commands with metadata.
- register_command: explicit API to register pre-built Command objects.
"""

import inspect
from typing import Dict, Optional, Callable, Any, Mapping
from core.commands import Command


class CommandRegistry:
    """Holds all command definitions and provides lookup utilities."""

    def __init__(self) -> None:
        # Primary name -> Command
        self._commands_by_name: Dict[str, Command] = {}
        # Alias name -> primary name
        self._alias_to_primary: Dict[str, str] = {}
        # Category -> description text
        self._category_descriptions: Dict[str, str] = {}

    # ---------------- Registration ----------------

    def register(self, command_obj: Command) -> None:
        """Register a command and its aliases, ensuring no collisions."""
        primary_key = command_obj.name.lower()

        if primary_key in self._commands_by_name or primary_key in self._alias_to_primary:
            raise ValueError(
                f"Command '{command_obj.name}' already registered.")

        self._commands_by_name[primary_key] = command_obj

        # Register alias mappings pointing to the primary name
        for alias in getattr(command_obj, "aliases", ()):
            alias_key = alias.lower()
            if alias_key in self._commands_by_name or alias_key in self._alias_to_primary:
                raise ValueError(
                    f"Alias '{alias}' for '{command_obj.name}' collides with an existing name."
                )
            self._alias_to_primary[alias_key] = primary_key

    # ---------------- Lookup ----------------

    def get(self, name: str) -> Optional[Command]:
        """Return the command by primary name or alias, or None if not found."""
        key = name.lower()
        if key in self._commands_by_name:
            return self._commands_by_name[key]
        if key in self._alias_to_primary:
            return self._commands_by_name[self._alias_to_primary[key]]
        return None

    def all(self) -> list[Command]:
        """Return only primary commands (avoid duplicates in UIs)."""
        return list(self._commands_by_name.values())

    def names(self) -> list[str]:
        """Return a list of all primary names and aliases for completion."""
        return [*self._commands_by_name.keys(), *self._alias_to_primary.keys()]

    # ---------------- Categories ----------------

    def categories(self) -> dict[str, list[Command]]:
        """Group commands by category for help output."""
        grouped: dict[str, list[Command]] = {}
        for cmd in self._commands_by_name.values():
            grouped.setdefault(cmd.category, []).append(cmd)
        return grouped

    def set_category_description(self, category: str, description: str) -> None:
        """Set display text for a category in help menus."""
        self._category_descriptions[category] = description.strip()

    def get_category_description(self, category: str) -> str:
        """Return display text for a category, or an empty string."""
        return self._category_descriptions.get(category, "")


# Global registry used across the app
REGISTRY = CommandRegistry()


def command(
    *,
    name: str | None = None,
    description: str | None = None,
    example: str | None = None,
    id: int | None = None,
    category: str | None = None,
    completers: Mapping[str, Callable[..., object]] | None = None,
    aliases: list[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to register a function as a CLI command with metadata.

    - Function name is transformed from snake_case to kebab-case for `name` if not provided.
    - `param_names` is captured from the function signature for future completion use.
    """

    def wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
        # Discover all parameter names (positional, kw-only, var-positional)
        signature = inspect.signature(func)
        param_names = [p.name for p in signature.parameters.values()]

        command_obj = Command(
            name=(name or func.__name__).replace("_", "-"),
            description=(description or (func.__doc__ or "")).strip(),
            example=example or "",
            id=id,
            callback=func,
            category=category or "general",
            completers=completers or {},
            aliases=aliases or [],
            param_names=param_names,
        )
        command_obj.module = func.__module__
        REGISTRY.register(command_obj)
        return func

    return wrapper


def register_command(command_obj: Command) -> None:
    """Explicit API for modules that construct Command objects directly."""
    REGISTRY.register(command_obj)
