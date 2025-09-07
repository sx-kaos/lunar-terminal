#!/usr/bin/env python3
# core/db/vault/__init__.py
from __future__ import annotations

"""
Vault keystore (SQLite + DPAPI-wrapped DEKs).
"""

from .keystore import (  # noqa: F401
    get_vault_db_path,
    init_keystore,
    create_or_rotate_workspace_key,
    load_workspace_key,
    keystore_exists,
)

__all__ = [
    "get_vault_db_path",
    "init_keystore",
    "create_or_rotate_workspace_key",
    "load_workspace_key",
    "keystore_exists",
]
