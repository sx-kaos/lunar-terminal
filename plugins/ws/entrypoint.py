# commands/ws/entrypoint.py
from __future__ import annotations

from typing import Iterable
from datetime import datetime

from core.commands import command, Command
from core.ui import print_table, print_line, set_terminal_title
from core.security import (
    create_secure_workspace,
    switch_secure_workspace,
    current_workspace_info,
)
from core.db import (
    list_workspaces,
    rename_workspace,
    archive_workspace,
    import_existing_workspaces,
    resolve_workspace,
)

CATEGORY_DESCRIPTION = "Manage secure workspaces (create, switch, list, rename, archive)."

def _fmt_ts(ts: str) -> str:
    """Format ISO8601 timestamps into human-readable local time."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts  # fallback if parsing fails


@command(
    name="ws-new",
    description="Create a new secure workspace and switch to it.",
    example="ws-new [nickname]",
    category="fs",
    aliases=["ws.create", "ws-add"],
)
def ws_new(nickname: str | None = None) -> str:
    create_secure_workspace(nickname=nickname or None)
    info = current_workspace_info() or {}
    nick = info.get("nickname") or info.get("slug") or info.get("id") or "(unknown)"
    return f"Created and switched to workspace: {nick}"


@command(
    name="ws-use",
    description="Switch to an existing workspace by id/slug/nickname (prefix OK).",
    example="ws-use <identifier>",
    category="fs",
    aliases=["ws.switch"],
)
def ws_use(identifier: str) -> str:
    try:
        # We let switch_secure_workspace call resolve (which now supports prefix)
        switch_secure_workspace(identifier)
        set_terminal_title(f"WS: {identifier}")
    except ValueError as exc:  # ambiguous
        return f"[error] {exc} Try 'ws-list' to see options."
    except FileNotFoundError as exc:
        return f"[error] {exc}"
    except Exception as exc:
        # If the catalog might be empty, suggest a scan
        return f"[error] {exc} (Tip: run 'ws-scan' to import existing folders.)"
    info = current_workspace_info() or {}
    nick = info.get("nickname") or info.get("slug") or info.get("id") or "(unknown)"
    return f"Switched to workspace: {nick}"


@command(
    name="ws-list",
    description="List workspaces (most recent first).",
    example="ws-list",
    category="fs",
    aliases=["ws.ls"],
)
def ws_list() -> None:
    rows_db = list_workspaces(include_archived=False)
    if not rows_db:
        print_line("No workspaces yet. Use 'ws-new [nickname]' to create one, or 'ws-scan' to import existing folders.")
        return
    rows = []
    current = current_workspace_info()
    cur_id = (current or {}).get("id")
    for r in rows_db:
        wid = r["id"]
        mark = "*" if cur_id and wid == cur_id else " "
        rows.append([
            mark,
            r["nickname"],
            r["id"][:8],
            _fmt_ts(r["created_at"]),
            _fmt_ts(r["last_used_at"]),
        ])
    print_table(rows, headers=["*", "Nickname", "ID", "Created", "Last Used"])


@command(
    name="ws-rename",
    description="Rename a workspace by id/slug/nickname.",
    example="ws-rename <identifier> <new_nickname>",
    category="fs",
    aliases=["ws.name"],
)
def ws_rename(identifier: str, new_nickname: str) -> str:
    rename_workspace(identifier, new_nickname)
    return "Workspace renamed."


@command(
    name="ws-archive",
    description="Archive (soft delete) a workspace by id/slug/nickname.",
    example="ws-archive <identifier>",
    category="fs",
    aliases=["ws.delete", "ws.del"],
)
def ws_archive_cmd(identifier: str) -> str:
    archive_workspace(identifier)
    return "Workspace archived."


@command(
    name="ws-current",
    description="Show the current workspace (nickname and short id).",
    example="ws-current",
    category="fs",
)
def ws_current() -> str:
    info = current_workspace_info()
    if not info:
        return "No active workspace."
    nick = info.get("nickname") or "(unnamed)"
    short_id = (info.get("id") or "")[:8]
    created_info = _fmt_ts(info.get("created_at") or "")
    last_used_info = _fmt_ts(info.get("last_used_at") or "")
    return f"{nick} ({short_id}) - Created: {created_info}, Last Used: {last_used_info}"


@command(
    name="ws-scan",
    description="Import any pre-existing workspace folders into the catalog.",
    example="ws-scan",
    category="fs",
)
def ws_scan() -> str:
    n = import_existing_workspaces()
    if n == 0:
        return "No new workspaces found."
    return f"Imported {n} workspace(s)."


COMMANDS: Iterable[Command] = ()
