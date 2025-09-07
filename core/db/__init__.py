#!/usr/bin/env python3
# core/db/__init__.py
from __future__ import annotations

"""
Package for database persistence and configuration.

Provides:
- Configuration loader with environment variable overrides (`config`).
- SQLite persistence for commands and workspace catalog (`db`).
- Helpers for initializing schema, syncing command registry, and managing workspaces.
"""


from .config import AppConfig, load_config, ensure_config_interactive, validate_or_create_config
from .db import (
    get_conn,
    get_connection,
    initialize_database,
    init_db,
    sync_registry_to_db,
    sync_registry_to_database,
    upsert_workspace,
    list_workspaces,
    resolve_workspace,
    rename_workspace,
    archive_workspace,
    touch_workspace_last_used,
    import_existing_workspaces,
    validate_catalog,
    DATABASE_FILE_PATH,
)

__all__ = [
    "AppConfig",
    "load_config",
    "get_conn",
    "get_connection",
    "initialize_database",
    "init_db",
    "sync_registry_to_db",
    "sync_registry_to_database",
    "upsert_workspace",
    "list_workspaces",
    "resolve_workspace",
    "rename_workspace",
    "archive_workspace",
    "touch_workspace_last_used",
    "import_existing_workspaces",
    "validate_catalog",
    "DATABASE_FILE_PATH",
    "ensure_config_interactive",
    "validate_or_create_config",
]
