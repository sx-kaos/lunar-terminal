#!/usr/bin/env python3
# core/security/secure_dir.py
from __future__ import annotations
"""
Secure working directory management + workspace catalog integration.

Changes:
- Remembers the last active workspace in a pointer file under the base root.
- On startup, re-opens the last workspace if it still exists; else creates a new one.
- Hardened on Windows: ACLs (SYSTEM + current user), EFS encryption, reparse-point
  (junction/symlink) blocking, and workspace-scoped TEMP.

Notes:
- No DB schema changes required.
- Pointer file is best-effort only; DB remains source of truth for metadata.
- All hardening is best-effort and non-fatal.
"""

import ctypes
import getpass
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# In-process globals (set on create/switch)
SECURE_WORKSPACE_ROOT: Path | None = None
CURRENT_WORKSPACE_ID: str | None = None

# Win32 file attribute flags (used to hide the directory and prevent indexing)
_FILE_ATTRIBUTE_HIDDEN = 0x2
_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400  # for junction/symlink detection

# Name of the file that stores the last-used workspace slug
_LAST_POINTER_NAME = ".last_workspace"

_HARDENED_MARKER = ".hardened"


def _has_been_hardened(path: Path) -> bool:
    try:
        return (path / _HARDENED_MARKER).is_file()
    except Exception:
        return False


def _mark_hardened(path: Path) -> None:
    try:
        (path / _HARDENED_MARKER).write_text(_now_iso(), encoding="utf-8")
        _windows_hide(path / _HARDENED_MARKER)
    except Exception:
        pass


def _windows_hide(path: Path) -> None:
    """Best-effort: set HIDDEN and NOT_CONTENT_INDEXED on Windows paths."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.kernel32.SetFileAttributesW(  # type: ignore[attr-defined]
            str(path),
            _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        )
    except Exception:
        # Non-fatal: hiding is a nicety, not a security boundary
        pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def base_workspace_root() -> Path:
    """
    Base directory where individual secure workspaces live:
      - Windows: %LOCALAPPDATA%/Lunar/workspace
      - POSIX:   ~/.lunar/workspace
    Ensures the directory exists and is hidden (Windows).
    """
    if os.name == "nt":
        base_dir = Path(os.environ.get(
            "LOCALAPPDATA", Path.home() / "AppData" / "Local"
        ))
        root = base_dir / "Lunar" / "workspace"
        root.mkdir(parents=True, exist_ok=True)
        _windows_hide(root)
        return root

    root = Path.home() / ".lunar" / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _last_pointer_path() -> Path:
    return base_workspace_root() / _LAST_POINTER_NAME


def _read_last_workspace_slug() -> Optional[str]:
    """Return the last-used workspace slug from pointer file, if present."""
    ptr = _last_pointer_path()
    try:
        text = ptr.read_text(encoding="utf-8").strip()
        return text or None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _write_last_workspace_slug(slug: str) -> None:
    """Persist the last-used workspace slug to pointer file (best-effort)."""
    try:
        p = _last_pointer_path()
        p.write_text(slug, encoding="utf-8")
        _windows_hide(p)
    except Exception:
        pass


# --------------------- Windows hardening helpers ---------------------

# ctypes wrappers kept minimal and defensive (no registry, no firewall)
if os.name == "nt":
    from ctypes import wintypes

    _ADVAPI = ctypes.WinDLL("Advapi32", use_last_error=True)
    _KERNEL = ctypes.WinDLL("Kernel32", use_last_error=True)

    EncryptFileW = _ADVAPI.EncryptFileW
    EncryptFileW.argtypes = [wintypes.LPCWSTR]
    EncryptFileW.restype = wintypes.BOOL

    GetFileAttributesW = _KERNEL.GetFileAttributesW
    GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    GetFileAttributesW.restype = wintypes.DWORD
else:
    EncryptFileW = None  # type: ignore[assignment]
    GetFileAttributesW = None  # type: ignore[assignment]


def _is_reparse_point(path: Path) -> bool:
    """Check if a path is a reparse point (junction/symlink) on Windows."""
    if os.name != "nt" or GetFileAttributesW is None:
        return False
    try:
        attrs = GetFileAttributesW(str(path))
        # INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF -> treat as not reparse
        return attrs != 0xFFFFFFFF and (attrs & _FILE_ATTRIBUTE_REPARSE_POINT) != 0
    except Exception:
        return False


def _assert_no_reparse_points(path: Path, root: Path) -> None:
    """
    Ensure none of the path components from root->path are reparse points.
    Blocks junction/symlink traversal even if final resolved path is inside root.
    """
    if os.name != "nt":
        return
    root = root.resolve()
    target = path.resolve()
    # Walk components under root towards target
    # Skip exact prefix equal to root
    root_parts = len(root.parts)
    cur = root
    for part in target.parts[root_parts:]:
        cur = cur / part
        if _is_reparse_point(cur):
            raise PermissionError(f"Reparse point blocked: {cur}")


def _harden_acls(path: Path) -> None:
    """
    Best-effort ACL hardening on Windows using 'icacls':
      - Remove inheritance
      - Grant SYSTEM and current user Full Control (OI)(CI) recursively
      - Remove broad groups if present (Users, Authenticated Users, Everyone)
    Non-fatal if 'icacls' is unavailable or domain/group names differ.
    """
    if os.name != "nt":
        return

    user = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    if domain and domain not in ("", "WORKGROUP"):
        user_id = f"{domain}\\{user}"
    else:
        user_id = user

    cmds = [
        ["icacls", str(path), "/inheritance:r"],  # Remove inheritance
        # Grant SYSTEM Full Control
        ["icacls", str(path), "/grant", "SYSTEM:(OI)(CI)(F)"],
        # Grant current user Full Control
        ["icacls", str(path), "/grant", f"{user_id}:(OI)(CI)(F)"],
        # The following may fail on non-English systems or if groups are absent - that's okay
        ["icacls", str(path), "/remove:g", "Users"],  # Remove Users group
        # Remove Authenticated Users group
        ["icacls", str(path), "/remove:g", "Authenticated Users"],
        # Remove Everyone group
        ["icacls", str(path), "/remove:g", "Everyone"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except Exception:
            # Keep going - better a partially tightened ACL than a crash
            pass


def _efs_encrypt(path: Path) -> None:
    """Per-user EFS encryption (best-effort). No-op if disabled by policy."""
    if os.environ.get("CST_DISABLE_EFS") in ("1", "true", "True", "TRUE"):
        return
    if os.name != "nt" or EncryptFileW is None:
        return
    try:
        # BOOL return; ignore failure
        EncryptFileW(str(path))
    except Exception:
        pass


def _isolate_temp(path: Path) -> None:
    """Confine TEMP/TMP for current process (and children) inside workspace."""
    try:
        tmp = path / ".tmp"
        tmp.mkdir(exist_ok=True)
        os.environ["TMP"] = str(tmp)
        os.environ["TEMP"] = str(tmp)
    except Exception:
        pass


def _finalize_hardening(path: Path) -> None:
    """
    Apply hardening only the first time for a workspace.
    Always re-scope TEMP, but skip ACL/EFS/hide if already done.
    """
    already = _has_been_hardened(path)
    if not already:
        _windows_hide(path)
        _harden_acls(path)
        _efs_encrypt(path)
        _mark_hardened(path)
    _isolate_temp(path)  # always


# ---------------------------- Core API ----------------------------

def _new_slug() -> str:
    # Opaque, DB- and FS-friendly identifier
    return uuid.uuid4().hex


def create_secure_workspace(
    nickname: str | None = None, *, slug: str | None = None
) -> Path:
    # LAZY IMPORT to avoid circular dependency
    from core.db.db import initialize_database, upsert_workspace
    # NEW: keystore imports (lazy)
    from core.db.vault import create_or_rotate_workspace_key

    base = base_workspace_root()
    slug_val = slug or _new_slug()
    path = (base / slug_val).resolve()
    path.mkdir(parents=True, exist_ok=True)
    _finalize_hardening(path)

    os.chdir(path)
    global SECURE_WORKSPACE_ROOT, CURRENT_WORKSPACE_ID
    SECURE_WORKSPACE_ROOT = path
    CURRENT_WORKSPACE_ID = slug_val

    initialize_database()
    nickname_val = nickname or f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    now = _now_iso()
    upsert_workspace(
        id_=slug_val,
        slug=slug_val,
        nickname=nickname_val,
        abs_path=str(path),
        created_at=now,
        last_used_at=now,
        tags_json="[]",
        archived=False,
    )

    # NEW: create a per-workspace DEK (DPAPI-wrapped in keystore)
    create_or_rotate_workspace_key(slug_val)

    _write_last_workspace_slug(slug_val)
    return path


def switch_secure_workspace(identifier: str) -> Path:
    # LAZY IMPORT to avoid circular dependency
    from core.db.db import resolve_workspace, touch_workspace_last_used, archive_workspace
    # NEW: keystore imports (lazy)
    from core.db.vault import load_workspace_key, create_or_rotate_workspace_key

    row = resolve_workspace(identifier)
    if not row:
        raise FileNotFoundError(f"No workspace matches '{identifier}'.")

    path = Path(row["abs_path"])
    if not path.exists():
        archive_workspace(row["id"])
        raise FileNotFoundError(
            f"Workspace path missing on disk and was archived: {path}"
        )

    _isolate_temp(path)

    os.chdir(path)
    touch_workspace_last_used(row["id"])

    global SECURE_WORKSPACE_ROOT, CURRENT_WORKSPACE_ID
    SECURE_WORKSPACE_ROOT = path
    CURRENT_WORKSPACE_ID = str(row["id"])

    # NEW: ensure the workspace has a DEK; create it if missing
    if load_workspace_key(None, None, CURRENT_WORKSPACE_ID) is None:
        create_or_rotate_workspace_key(CURRENT_WORKSPACE_ID)

    _write_last_workspace_slug(str(row["slug"]))
    return path


def _switch_to_last_if_possible() -> Optional[Path]:
    """
    Best-effort: load the last-used workspace recorded in the pointer file.
    Returns the path if successful, else None.
    """
    slug = _read_last_workspace_slug()
    if not slug:
        return None
    try:
        return switch_secure_workspace(slug)
    except Exception:
        return None


def setup_secure_workspace(override: str | None = None) -> Path:
    """
    Initializer:
    - If override is provided, use it as the *base* folder and create a new subfolder.
    - Otherwise, try to switch to the last used workspace; if unavailable, create a new one.
    """
    if override:
        base = Path(override).expanduser().resolve()
        base.mkdir(parents=True, exist_ok=True)
        try:
            _windows_hide(base)
        except Exception:
            pass
        return create_secure_workspace()

    # Try re-opening the last workspace first
    existing = _switch_to_last_if_possible()
    if existing is not None:
        return existing

    # Fallback: create a fresh workspace
    return create_secure_workspace()


def resolve_in_sandbox(user_supplied_path: str | os.PathLike[str]) -> Path:
    """
    Resolve a user-supplied path strictly within the active secure workspace.
    Additionally, deny traversal through any reparse point (junction/symlink)
    anywhere under the workspace on Windows.
    """
    if SECURE_WORKSPACE_ROOT is None:
        raise RuntimeError(
            "Secure workspace not initialized. Create/switch a workspace first."
        )

    path_obj = Path(user_supplied_path)
    base_dir = Path.cwd() if not path_obj.is_absolute() else Path(path_obj.anchor or "/")
    resolved_path = (base_dir / path_obj if base_dir != Path("/") else path_obj).resolve()

    try:
        # type: ignore[attr-defined]
        if not resolved_path.is_relative_to(SECURE_WORKSPACE_ROOT):
            raise PermissionError("Path escapes secure workspace.")
    except AttributeError:
        if not str(resolved_path).lower().startswith(str(SECURE_WORKSPACE_ROOT).lower()):
            raise PermissionError("Path escapes secure workspace.")

    # NEW: deny any junction/symlink traversal under the workspace
    _assert_no_reparse_points(resolved_path, SECURE_WORKSPACE_ROOT)
    return resolved_path


def current_workspace_info() -> Optional[dict[str, str]]:
    """
    Return the DB record for the current workspace, if any.
    """
    if not CURRENT_WORKSPACE_ID:
        return None
    # LAZY IMPORT to avoid circular dependency
    from core.db.db import resolve_workspace

    row = resolve_workspace(CURRENT_WORKSPACE_ID)
    return dict(row) if row else None


def adopt_current_cwd_as_workspace(nickname: str | None = None) -> Path:
    """
    Register the current working directory as a workspace (if not present),
    set it active, and return the path. Useful to adopt pre-existing folders.
    """
    # LAZY IMPORT to avoid circular dependency
    from core.db.db import initialize_database, resolve_workspace, upsert_workspace

    path = Path.cwd().resolve()
    base = base_workspace_root().resolve()
    try:
        if not path.is_relative_to(base):
            raise PermissionError("CWD is outside the base workspace root.")
    except AttributeError:
        if not str(path).lower().startswith(str(base).lower()):
            raise PermissionError("CWD is outside the base workspace root.")

    # Best-effort hardening when adopting (won't break if insufficient rights)
    _finalize_hardening(path)

    slug = path.name
    initialize_database()
    if not resolve_workspace(slug):
        now = _now_iso()
        upsert_workspace(
            id_=slug,
            slug=slug,
            nickname=nickname or f"adopted-{slug[:8]}",
            abs_path=str(path),
            created_at=now,
            last_used_at=now,
            tags_json="[]",
            archived=False,
        )

    global SECURE_WORKSPACE_ROOT, CURRENT_WORKSPACE_ID
    SECURE_WORKSPACE_ROOT = path
    CURRENT_WORKSPACE_ID = slug

    # Update the pointer file
    _write_last_workspace_slug(slug)
    return path
