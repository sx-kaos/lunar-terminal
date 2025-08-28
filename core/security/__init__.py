#!/usr/bin/env python3
# core/security/__init__.py
from __future__ import annotations

"""
Package for secure workspace management and filesystem path sanitization.

Provides:
- Workspace lifecycle: create, switch, adopt, setup, current info.
- Strict path resolution / sandboxing (`resolve_in_sandbox`).
- Path sanitization helpers (`sanitize_path`, `sandbox_paths`, `PATHY_KEYS`, `is_path_annotation`).
- In-process state: `SECURE_WORKSPACE_ROOT`, `CURRENT_WORKSPACE_ID`.
- Windows hardening (ACLs, EFS, reparse-point blocking, per-workspace TEMP).
"""


# Re-export secure workspace API
from . import secure_dir as _secure
from .secure_dir import *  # noqa: F401,F403

# Re-export sanitization helpers
from . import sanitize as _sanitize
from .sanitize import *  # noqa: F401,F403

# Public surface
_names = {n for n in dir(_secure) if not n.startswith("_")} | {
    n for n in dir(_sanitize) if not n.startswith("_")
}
__all__ = sorted(_names)  # type: ignore | Public API surface
