#!/usr/bin/env python3
# core/interface/loader.py
from __future__ import annotations

"""
Dynamic command loader.

Features:
- Imports all modules under a given package (default: 'plugins').
- Supports 'entrypoint.py' inside a subpackage registering COMMAND/COMMANDS.
- Derives categories from module paths if not explicitly set.
- Collects category descriptions from either CATEGORY_DESCRIPTION or module docstring.
"""

import importlib
import pkgutil
from pathlib import Path
from types import ModuleType
from typing import Iterable

from core.commands import REGISTRY
from core.commands import Command


def _register_from_entry_module(module: ModuleType) -> int:
    """Register COMMAND/COMMANDS exported by an entry module, if present."""
    registered_count = 0
    if hasattr(module, "COMMAND"):
        obj = getattr(module, "COMMAND")
        if isinstance(obj, Command):
            REGISTRY.register(obj)
            registered_count += 1
    if hasattr(module, "COMMANDS"):
        objs = getattr(module, "COMMANDS")
        if isinstance(objs, Iterable):
            for item in objs:
                if isinstance(item, Command):
                    REGISTRY.register(item)
                    registered_count += 1
    return registered_count


def load_commands(commands_package: str = "plugins") -> int:
    """
    Import all modules under the given package (e.g., 'plugins').

    Supported layouts:
      1) Plain modules: commands/foo.py  -> import commands.foo
      2) Packages with an entrypoint: commands/bar/entrypoint.py
         -> import commands.bar.entrypoint
            and register COMMAND/COMMANDS if present.

    Works with regular and namespace packages.
    """

    package = importlib.import_module(commands_package)
    package_paths = [str(p) for p in getattr(package, "__path__", [])]

    if not package_paths:
        raise RuntimeError(
            f"'{commands_package}' must be a package (folder) with modules. "
            "Create a 'plugins' directory and optionally an __init__.py."
        )

    loaded_count = 0
    discovered_subpackages: set[str] = set()

    for base_path in package_paths:
        for modinfo in pkgutil.iter_modules([base_path]):
            module_name = modinfo.name
            if module_name.startswith("_"):
                # Ignore private modules
                continue

            if modinfo.ispkg:
                discovered_subpackages.add(module_name)
                entrypoint_path = Path(
                    base_path) / module_name / "entrypoint.py"
                if entrypoint_path.exists():
                    module = importlib.import_module(
                        f"{commands_package}.{module_name}.entrypoint")
                    loaded_count += 1
                    _register_from_entry_module(module)
                else:
                    importlib.import_module(
                        f"{commands_package}.{module_name}")
                    loaded_count += 1
            else:
                importlib.import_module(
                    f"{commands_package}.{module_name}")
                loaded_count += 1

    _assign_categories_from_modules(commands_package)
    _collect_category_descriptions(
        commands_package, discovered_subpackages)

    # Optional: could log this timing using UIutils.init_logger if desired.
    return loaded_count


def _assign_categories_from_modules(commands_package: str) -> None:
    """
    Derive category from first subpackage segment (e.g. 'recon.portscan')
    if not explicitly set (default 'general').
    """
    prefix = f"{commands_package}."
    for command_obj in REGISTRY.all():
        if command_obj.category != "general" or not command_obj.module.startswith(prefix):
            continue
        relative = command_obj.module[len(prefix):]
        segments = relative.split(".")
        if len(segments) >= 2:
            command_obj.category = segments[0]


def _collect_category_descriptions(commands_package: str, subpackages: set[str]) -> None:
    """
    Category description is taken from:
      1) commands.<category>.CATEGORY_DESCRIPTION (string), or
      2) commands.<category> module docstring (__doc__), else "".
    """
    for category in subpackages:
        try:
            module = importlib.import_module(
                f"{commands_package}.{category}")
        except Exception:
            continue

        description_text = ""
        value = getattr(module, "CATEGORY_DESCRIPTION", None)
        if isinstance(value, str):
            description_text = value.strip()
        elif isinstance(getattr(module, "__doc__", None), str):
            description_text = (module.__doc__ or "").strip()

        REGISTRY.set_category_description(category, description_text)
