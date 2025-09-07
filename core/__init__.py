#!/usr/bin/env python3
# core/__init__.py
from __future__ import annotations
"""
Core package bootstrap.

Avoid eager imports/aliases that trigger package initialization cascades.
Only alias legacy single-file modules to their new locations.

Notes:
- Do NOT alias package names like 'core.commands' or 'core.interface.*'.
- Let 'core.commands' and 'core.interface' expose their APIs via their own
  __init__.py files.
"""


# Optional convenience re-exports (keep minimal; no interface wiring here)
try:
    from core.commands import Command, REGISTRY, command  # noqa: F401
except Exception:
    # Don't fail package import if commands package isn't ready.
    pass
