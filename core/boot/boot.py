#!/usr/bin/env python3
# core/boot/boot.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
import os
import platform
import shutil
import time

from core.commands import REGISTRY
from core.db import (
    load_config,
    initialize_database,
    import_existing_workspaces,
    validate_catalog,
    sync_registry_to_database,
)
from core.helpers import SysInfo, get_sysinfo
from core.interface.loader import load_commands as _load_cmds
from core.interface import _is_admin_user
from core.security import setup_secure_workspace, base_workspace_root
from core.ui import (
    colorize,
    enable_windows_vt,
    init_logger,
    print_line,
    set_terminal_title,
)


@dataclass(slots=True)
class BootState:
    root: Path
    logger: Any
    config: Any
    loaded_count: int
    sysinfo: SysInfo


def _step(label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
    except Exception as exc:
        print_line(
            colorize(f"[FAILED] {label} ({type(exc).__name__}: {exc})", "red"))
        raise
    print_line(colorize(f"[  OK  ] {label}", "green"))
    return out


def _ps_available() -> bool:
    for exe in ("pwsh", "powershell"):
        if shutil.which(exe):
            return True
    return False


def _temp_scoped_to(workspace: Path) -> bool:
    tmp = os.environ.get("TMP", "") or os.environ.get("TEMP", "") or ""
    try:
        return Path(tmp).resolve().as_posix().startswith(workspace.resolve().as_posix())
    except Exception:
        return False


def _touch_history_file() -> Optional[Path]:
    # keep in sync with core.interface.cli.HISTORY_FILE_PATH
    hist = Path.home() / ".cybersec_history"
    try:
        hist.touch(exist_ok=True)
        return hist
    except Exception:
        return None


def boot_sequence() -> BootState:
    # ---------- console + env ----------
    _step("Enable ANSI sequences", enable_windows_vt)
    _step(f"Detect environment: {platform.system()} {platform.release()} / Python {platform.python_version()}",
          lambda: None)
    _step("Privilege check (admin/root)", lambda: _is_admin_user())

    # ---------- config ----------
    config = _step("Load configuration", load_config)

    # ---------- workspace ----------
    base_root = _step("Resolve workspace base directory", base_workspace_root)
    root = _step(
        "Open secure workspace",
        lambda: setup_secure_workspace(
            getattr(config, "workspace_override", None)),
    )
    set_terminal_title(f"WS: {root.name}")

    # Cosmetic/diagnostic steps around workspace state
    _step("Verify hardening marker (.hardened) or first-run",
          lambda: (root / ".hardened").exists() or None)
    _step("Check TEMP/TMP scoped to workspace", lambda: _temp_scoped_to(root))

    # ---------- logging ----------
    logger = _step(
        "Initialize logger",
        lambda: init_logger("cybersec", logfile=getattr(
            config, "log_file_path", None)),
    )

    # ---------- database prep ----------
    _step("Initialize catalog database (if missing)", initialize_database)
    _step("Import orphaned workspaces into catalog", import_existing_workspaces)
    _step("Validate catalog references on disk", validate_catalog)

    # ---------- system info (parallel) ----------
    with ThreadPoolExecutor(max_workers=2) as pool:
        sysinfo_future = pool.submit(get_sysinfo)

        # ---------- commands ----------
        pkg_name = getattr(config, "commands_package", "plugins")
        _step(f"Locate commands package '{pkg_name}'",
              lambda: __import__(pkg_name))
        loaded_count = _step("Discover command modules",
                             lambda: _load_cmds(pkg_name))

        # ---------- registry & completion warmup ----------
        _step("Warm command names for completion", lambda: REGISTRY.names())
        _step("Collect category descriptions", lambda: REGISTRY.categories())

        # ---------- optional DB sync ----------
        if getattr(config, "sync_db_on_start", True):
            _step("Sync command registry to DB", sync_registry_to_database)
        else:
            _step("Skip DB sync (config)", lambda: None)

        # ---------- sysinfo finalize ----------
        sysinfo = _step("Probe system information", sysinfo_future.result)

    # ---------- diagnostics / niceties ----------
    _step(
        f"PowerShell available: {'yes' if _ps_available() else 'no'}", lambda: None)
    _step("Prepare history file", _touch_history_file)
    _step("Finalize terminal title", lambda: set_terminal_title(
        f"WS: {root.name} • {loaded_count} cmds"))

    # ---------- done ----------
    _step("Boot complete", lambda: None)

    return BootState(
        root=root,
        logger=logger,
        config=config,
        loaded_count=loaded_count,
        sysinfo=sysinfo,
    )
