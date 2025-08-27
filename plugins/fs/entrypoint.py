# commands/fs/entrypoint.py
from __future__ import annotations

import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Iterable

from core.commands import command, Command
from core.ui import print_table, print_line
from core.security import (
    resolve_in_sandbox,
    SECURE_WORKSPACE_ROOT,
    current_workspace_info,
)

CATEGORY_DESCRIPTION = "Work with files in the secure workspace."


# -------------------------- helpers --------------------------

def _fmt_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f} {units[i]}"

def _workspace_label() -> str:
    """Nickname if available, else the slug/id; never an absolute path."""
    info = current_workspace_info()
    if not info:
        return "(no-workspace)"
    nick = (info.get("nickname") or "").strip()
    return nick if nick else (info.get("slug") or info.get("id") or "(unknown)")

def _relative_to_workspace(p: Path) -> str:
    root = SECURE_WORKSPACE_ROOT
    if root:
        try:
            rel = p.resolve().relative_to(root.resolve())
            return str(rel) if str(rel) != "" else "."
        except Exception:
            pass
    return "."


# ----------------------- commands (decorator) -----------------------

@command(
    name="fs.write",
    description="Write piped text to a file inside the sandbox.",
    example="... | fs.write path=out.txt append=true",
    category="fs",
    aliases=["write"],
)
def fs_write(*, path: str, append: bool = False, _in: str | None = None) -> str:
    """
    Write stdin/_in to a sandboxed file (creates parent dirs).
    """
    p = resolve_in_sandbox(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = _in or ""
    mode = "a" if append else "w"
    with p.open(mode, encoding="utf-8", newline="") as f:
        f.write(data)
    return ""


# ----------------------- commands (callables) -----------------------

def dir_cmd(path: str = ".") -> None:
    """
    List directory contents in the sandbox (like 'ls'/'dir').
    If 'path' points to a file, list its parent.
    """
    target = resolve_in_sandbox(path if path else ".")
    show_dir = target if target.is_dir() else target.parent

    rows = []
    try:
        for entry in sorted(show_dir.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            t = "<DIR>" if entry.is_dir() else "FILE"
            size = "" if entry.is_dir() else _fmt_size(entry.stat().st_size)
            mtime = datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            rows.append([entry.name, t, size, mtime])
    except PermissionError:
        print_line("Permission denied.")
        return

    ws_label = _workspace_label()
    rel_path = _relative_to_workspace(show_dir)
    print_line(f"Workspace: {ws_label}    Path: {rel_path}")
    print_table(rows, headers=["Name", "Type", "Size", "Modified"])


def cd_cmd(path: str) -> None:
    """
    Change current working directory within the sandbox.
    """
    p = resolve_in_sandbox(path)
    if not p.exists() or not p.is_dir():
        print_line("Directory not found.")
        return
    os.chdir(p)
    rel = _relative_to_workspace(p)
    print_line(f"Changed directory to: {rel}")


def mkdir_cmd(path: str) -> None:
    """
    Create a directory (including parents) inside the sandbox.
    """
    p = resolve_in_sandbox(path)
    p.mkdir(parents=True, exist_ok=True)


def mkfile_cmd(path: str, *, text: str = "") -> None:
    """
    Create/overwrite a file with optional initial text.
    """
    p = resolve_in_sandbox(path)
    if p.exists() and p.is_dir():
        print_line("Path is a directory.")
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def copy_cmd(src: str, dst: str) -> None:
    """
    Copy a file inside the sandbox.
    """
    s = resolve_in_sandbox(src)
    d = resolve_in_sandbox(dst)
    if not s.exists() or not s.is_file():
        print_line(f"Source file not found: {src}")
        return
    if d.exists() and d.is_dir():
        d = d / s.name
    d.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(s, d)
    print_line(f"Copied to: {d.name}")


def rename_cmd(src: str, dst: str) -> None:
    """
    Rename or move a file/directory within the sandbox (atomic when possible).
    """
    s = resolve_in_sandbox(src)
    d = resolve_in_sandbox(dst)
    if not s.exists():
        print_line(f"Not found: {src}")
        return
    d.parent.mkdir(parents=True, exist_ok=True)
    os.replace(s, d)
    print_line(f"Renamed to: {d.name}")


def delete_cmd(path: str) -> None:
    """
    Delete a file. (Refuses to remove directories.)
    """
    p = resolve_in_sandbox(path)
    if not p.exists():
        print_line("Not found.")
        return
    if p.is_dir():
        print_line("Refusing to remove a directory. (Use 'rmdir' with --recursive later.)")
        return
    try:
        p.unlink()
        print_line("Deleted.")
    except PermissionError as e:
        print_line(f"Permission error: {e}")


def cat_cmd(path: str) -> None:
    """
    Print file contents (UTF-8, errors replaced).
    """
    p = resolve_in_sandbox(path)
    if not p.exists() or not p.is_file():
        print_line("File not found.")
        return
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                print_line(line.rstrip("\n"))
    except Exception as e:
        print_line(f"Error reading file: {e}")


# ----------------------- registry objects -----------------------

COMMANDS: Iterable[Command] = (
    Command(
        name="dir",
        description="List directory contents",
        example="dir [path]",
        callback=dir_cmd,
        category="fs",
        aliases=["ls"],
    ),
    Command(
        name="cd",
        description="Change directory within the sandbox",
        example="cd <path>",
        callback=cd_cmd,
        category="fs",
    ),
    Command(
        name="mkdir",
        description="Create a directory (including parents)",
        example="mkdir <path>",
        callback=mkdir_cmd,
        category="fs",
    ),
    Command(
        name="mkfile",
        description="Create/overwrite a file with optional text",
        example='mkfile <path> text="hello"',
        callback=mkfile_cmd,
        category="fs",
    ),
    Command(
        name="copy",
        description="Copy a file",
        example="copy <src> <dst>",
        callback=copy_cmd,
        category="fs",
    ),
    Command(
        name="rename",
        description="Rename/move a file or directory",
        example="rename <src> <dst>",
        callback=rename_cmd,
        category="fs",
    ),
    Command(
        name="delete",
        description="Delete a file",
        example="delete <path>",
        callback=delete_cmd,
        category="fs",
        aliases=["del", "rm"],
    ),
    Command(
        name="cat",
        description="Print file contents",
        example="cat <path>",
        callback=cat_cmd,
        category="fs",
        aliases=["read", "open"],
    ),
)
