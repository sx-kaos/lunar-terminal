#!/usr/bin/env python3
# core/db/db.py
from __future__ import annotations
"""
SQLite persistence for command metadata AND workspace catalog.

The database is GLOBAL (shared by all workspaces):
  Windows: %LOCALAPPDATA%/Lunar/workspace/catalog.db
  POSIX:   ~/.lunar/workspace/catalog.db
"""

import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


from core.commands import REGISTRY
from core.security import base_workspace_root

# ---------- DB path (GLOBAL) ----------


def _catalog_path() -> Path:
    base = base_workspace_root()
    base.mkdir(parents=True, exist_ok=True)
    return (base / "catalog.db").resolve()


DB_FILE = _catalog_path()                 # NEW: global DB location
DATABASE_FILE_PATH = DB_FILE              # keep alias for callers


def _open_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_conn() -> sqlite3.Connection:  # old alias
    return _open_connection()


def get_connection() -> sqlite3.Connection:  # new
    return _open_connection()


def initialize_database() -> None:
    with _open_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                example TEXT NOT NULL DEFAULT '',
                module TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                slug TEXT UNIQUE NOT NULL,
                nickname TEXT NOT NULL,
                abs_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                archived INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ws_last_used ON workspaces(last_used_at DESC)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ws_nickname ON workspaces(nickname)")


def init_db() -> None:  # old alias
    initialize_database()


def sync_registry_to_db() -> None:  # old name
    _sync_registry_common()


def sync_registry_to_database() -> None:  # new name
    _sync_registry_common()


def _sync_registry_common() -> None:
    initialize_database()
    with _open_connection() as conn:
        for cmd in REGISTRY.all():
            conn.execute(
                """
                INSERT INTO commands (name, description, example, module)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    description = excluded.description,
                    example = excluded.example,
                    module = excluded.module
                """,
                (cmd.name, cmd.description, cmd.example, cmd.module),
            )
        rows = conn.execute("SELECT id, name FROM commands").fetchall()
        id_by_name = {name.lower(): cid for cid, name in rows}

    for cmd in REGISTRY.all():
        cmd.id = id_by_name.get(cmd.name.lower())


# -------- workspace catalog --------

def upsert_workspace(
    *,
    id_: str,
    slug: str,
    nickname: str,
    abs_path: str,
    created_at: str,
    last_used_at: str,
    tags_json: str = "[]",
    archived: bool = False,
) -> None:
    initialize_database()
    with _open_connection() as conn:
        conn.execute(
            """
            INSERT INTO workspaces (id, slug, nickname, abs_path, created_at, last_used_at, tags, archived)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                nickname = excluded.nickname,
                abs_path = excluded.abs_path,
                last_used_at = excluded.last_used_at,
                tags = excluded.tags,
                archived = excluded.archived
            """,
            (id_, slug, nickname, abs_path, created_at,
             last_used_at, tags_json, int(archived)),
        )


def list_workspaces(*, include_archived: bool = False) -> list[sqlite3.Row]:
    initialize_database()
    # auto-heal before listing
    validate_catalog(prune_missing=True)

    flag = 1 if include_archived else 0
    with _open_connection() as conn:
        return list(
            conn.execute(
                "SELECT * FROM workspaces WHERE archived=? ORDER BY last_used_at DESC",
                (flag,),
            ).fetchall()
        )


def _find_by_prefix(col: str, prefix: str) -> list[sqlite3.Row]:
    with _open_connection() as conn:
        return list(
            conn.execute(
                f"SELECT * FROM workspaces WHERE archived=0 AND {col} LIKE ? ESCAPE '\\'",
                (prefix.replace("%", "\\%").replace("_", "\\_") + "%",),
            ).fetchall()
        )


def resolve_workspace(identifier: str) -> Optional[sqlite3.Row]:
    """
    Find a single workspace by id, slug, or nickname (active only).
    Accepts 6-12 char prefix of the id for convenience.
    """
    initialize_database()
    validate_catalog(prune_missing=True)
    ident = identifier.strip()
    with _open_connection() as conn:
        # 1) exact matches first
        for col in ("id", "slug", "nickname"):
            row = conn.execute(
                f"SELECT * FROM workspaces WHERE {col}=? AND archived=0",
                (ident,),
            ).fetchone()
            if row:
                return row

        # 2) short-id prefix on id
        if 6 <= len(ident) <= 12:
            rows = conn.execute(
                "SELECT * FROM workspaces WHERE id LIKE ? AND archived=0",
                (f"{ident}%",),
            ).fetchall()
            if len(rows) == 1:
                return rows[0]
            # 0 or ambiguous -> no match
    return None


def rename_workspace(id_or_slug: str, new_nickname: str) -> None:
    initialize_database()
    with _open_connection() as conn:
        conn.execute(
            """
            UPDATE workspaces SET nickname=?
            WHERE (id=? OR slug=?) AND archived=0
            """,
            (new_nickname, id_or_slug, id_or_slug),
        )


def archive_workspace(id_or_slug: str) -> None:
    initialize_database()
    with _open_connection() as conn:
        conn.execute(
            "UPDATE workspaces SET archived=1 WHERE (id=? OR slug=?)",
            (id_or_slug, id_or_slug),
        )


def touch_workspace_last_used(id_: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    initialize_database()
    with _open_connection() as conn:
        conn.execute(
            "UPDATE workspaces SET last_used_at=? WHERE id=?", (now, id_))


# ---- importer for pre-existing folders ----

def import_existing_workspaces() -> int:
    """
    Scan the base workspace directory for subfolders and insert any that
    are missing from the catalog. Returns the number of imported rows.
    """
    initialize_database()

    base = base_workspace_root()
    count = 0
    with _open_connection() as conn:
        for child in base.iterdir():
            if not child.is_dir():
                continue
            slug = child.name
            # Only import "opaque" 32-hex slugs (keeps it tidy); relax if needed.
            if len(slug) != 32 or any(c not in "0123456789abcdef" for c in slug.lower()):
                continue
            row = conn.execute(
                "SELECT 1 FROM workspaces WHERE slug=? OR id=?", (slug, slug)).fetchone()
            if row:
                continue
            try:
                stat = child.stat()
                created = getattr(stat, "st_ctime", stat.st_mtime)
                ts = datetime.utcfromtimestamp(created).replace(
                    tzinfo=timezone.utc).isoformat()
            except Exception:
                ts = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO workspaces (id, slug, nickname, abs_path, created_at, last_used_at, tags, archived)
                VALUES (?, ?, ?, ?, ?, ?, '[]', 0)
                """,
                (slug, slug, f"adopted-{slug[:8]}",
                 str(child.resolve()), ts, ts),
            )
            count += 1
    return count

# --- catalog validation / self-healing ---


def validate_catalog(*, prune_missing: bool = True) -> int:
    """
    Ensure catalog rows refer to existing folders.
    - If a workspace 'abs_path' no longer exists and prune_missing=True,
      mark it archived=1.
    Returns the number of rows modified (archived).
    """
    initialize_database()
    changed = 0
    with _open_connection() as conn:
        rows = conn.execute(
            "SELECT id, abs_path FROM workspaces WHERE archived=0"
        ).fetchall()
        for r in rows:
            p = Path(r["abs_path"])
            if not p.exists():
                if prune_missing:
                    conn.execute(
                        "UPDATE workspaces SET archived=1 WHERE id=?",
                        (r["id"],),
                    )
                    changed += 1
    return changed
