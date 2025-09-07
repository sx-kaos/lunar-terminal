#!/usr/bin/env python3
# core/interface/__init__.py
from __future__ import annotations

"""
Package for interactive console interface and command dispatch.

Provides:
- CLI frontends with history and completion (prompt_toolkit / readline / plain).
- Token-aware completion helpers.
- Parser utilities for binding arguments to command functions.
- Command dispatcher and help formatting.
- Dynamic command loader for the plugins package.
"""


# Completion FIRST (cli depends on it)
from .completion import suggest, BUILT_IN_COMMANDS

# Parser utilities
from .parser import tokenize, bind_args, build_usage

# Command dispatcher / help
from .handler import handle_line, HELP_TEXT, list_categories, format_command_help

# Loader
from .loader import load_commands

# CLI frontends (after completion is available)
from .cli import (
    BaseCLI,
    PromptToolkitCLI,
    ReadlineCLI,
    make_cli,
    HISTORY_FILE_PATH,
    _is_admin_user
)

__all__ = [
    # completion
    "suggest",
    "BUILT_IN_COMMANDS",
    # parser
    "tokenize",
    "bind_args",
    "build_usage",
    # handler
    "handle_line",
    "HELP_TEXT",
    "list_categories",
    "format_command_help",
    # loader
    "load_commands",
    # cli
    "BaseCLI",
    "PromptToolkitCLI",
    "ReadlineCLI",
    "make_cli",
    "HISTORY_FILE_PATH",
    "_is_admin_user"
]
