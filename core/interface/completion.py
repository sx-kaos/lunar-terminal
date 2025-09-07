#!/usr/bin/env python3
# core/interface/completion.py
from __future__ import annotations

"""
Command line completion utilities.

This module offers token-aware suggestions for:
- First token: built-in commands + all registered command names and aliases.
- 'help <partial>': suggests categories and command names.
- Subsequent tokens: argument keys (key=) and values via per-command completers.
"""

import shlex
from core.commands import REGISTRY

# Built-in verbs always available
BUILT_IN_COMMANDS: tuple[str, ...] = (
    "help", "exit", "quit", "clear", "cls")


def _split_current_token(raw_input: str) -> tuple[list[str], str]:
    """
    Return (parts, current_prefix).

    Behavior:
      - Use shlex.split for shell-like parsing (POSIX).
      - If trailing whitespace exists, append an empty token to signal a new one.
      - On malformed quotes, fall back to whitespace splitting.
    """
    if not raw_input:
        return [], ""

    try:
        parts = shlex.split(raw_input, posix=True)
        if raw_input[-1].isspace():
            parts.append("")
    except ValueError:
        parts = raw_input.split()
        if raw_input[-1].isspace():
            parts.append("")
    current_prefix = parts[-1] if parts else ""
    return parts, current_prefix


def _split_key_value(token: str) -> tuple[str | None, str]:
    """If token appears as 'key=value' return (key, value_prefix), else (None, token)."""
    if "=" in token:
        key, value = token.split("=", 1)
        return key, value
    return None, token


def _category_names() -> list[str]:
    """Return all known category names from the registry."""
    return list(REGISTRY.categories().keys())


def suggest(text_before_cursor: str) -> list[str]:
    """
    Produce suggestions based on the current buffer content.

    Strategy:
      1) If entering the first token, suggest built-ins and all command names/aliases.
      2) If the first token is 'help', suggest categories and command names for the second token.
      3) For known commands, suggest:
         - parameter keys as 'name='
         - parameter values using the command's completer providers
         - positional arguments via providers 'posN' or 'pos*'
    """
    raw_buffer = text_before_cursor.lstrip()
    parts, current_prefix = _split_current_token(raw_buffer)

    # First token: propose built-ins and commands (names + aliases).
    if len(parts) <= 1:
        universe = [*BUILT_IN_COMMANDS, *REGISTRY.names()]
        return sorted([w for w in universe if w.startswith(current_prefix)])

    # Special handling for: help <partial>
    first_token = parts[0]
    if first_token == "help":
        target_prefix = parts[1] if len(parts) >= 2 else ""
        # Suggest both category names and command names/aliases
        universe = set(_category_names() + REGISTRY.names())
        return sorted([w for w in universe if w.startswith(target_prefix)])

    # We are completing arguments for a specific command
    command_name = parts[0]
    command_obj = REGISTRY.get(command_name)
    if not command_obj:
        return []

    argument_tokens = parts[1:]
    current_token = argument_tokens[-1] if argument_tokens else ""
    key, value_prefix = _split_key_value(current_token)

    # Suggest parameter keys when typing the key segment (exclude positional markers)
    if key is None and current_token and not current_token.startswith("-"):
        parameter_keys = [
            k for k in command_obj.completers.keys() if not k.startswith("pos")]
        # Also allow plain param names (registered from signature), surfaced as "name="
        parameter_keys = sorted(
            set(parameter_keys + [p for p in command_obj.param_names if p != "args"]))
        return [f"{k}=" for k in parameter_keys if f"{k}=".startswith(current_token)]

    # Suggest values for key=value patterns using the provider
    if key is not None:
        provider = command_obj.completers.get(key)
        if not provider:
            return []
        return [f"{key}={value}" for value in provider(text=value_prefix, argv=argument_tokens, index=None)] # type: ignore[return-value]

    # Positional argument suggestions
    positional_only = [
        token for token in argument_tokens if "=" not in token]
    position_index = max(0, len(positional_only) - 1)
    provider = command_obj.completers.get(
        f"pos{position_index}") or command_obj.completers.get("pos*")
    if not provider:
        return []
    return list(provider(text=current_token, argv=argument_tokens, index=position_index)) # type: ignore[return-value]
