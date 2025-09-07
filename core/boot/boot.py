#!/usr/bin/env python3
# core/boot/boot.py
from __future__ import annotations
"""
Boot sequence for Lunar Terminal.

Goals:
- Reduce boot time by parallelizing slow tasks (sysinfo, DB sync, file marking).
- Add lightweight caching for repeated work (workspace file marking, sysinfo).
- Maintain clear status output for each boot step.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
import os
import platform
import shutil

from core.commands import REGISTRY
from core.db import (
    initialize_database,
    import_existing_workspaces,
    validate_catalog,
    sync_registry_to_database,
    validate_or_create_config,
)
from core.helpers import SysInfo, get_sysinfo
from core.interface.loader import load_commands as _load_cmds
from core.interface import _is_admin_user
from core.security import setup_secure_workspace
from core.security.secure_dir import _windows_hide
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
    """Run a boot step with status output."""
    try:
        out = fn()
    except Exception as exc:
        print_line(
            colorize(f"[FAILED] {label} ({type(exc).__name__}: {exc})", "red")
        )
        raise
    print_line(colorize(f"[  OK  ] {label}", "green"))
    return out


def _ps_available() -> bool:
    """Check if PowerShell is available in PATH."""
    for exe in ("pwsh", "powershell"):
        if shutil.which(exe):
            return True
    return False


def _temp_scoped_to(workspace: Path) -> bool:
    """Check if TMP/TEMP is scoped under the workspace root."""
    tmp = os.environ.get("TMP", "") or os.environ.get("TEMP", "") or ""
    try:
        return Path(tmp).resolve().as_posix().startswith(
            workspace.resolve().as_posix()
        )
    except Exception:
        return False


def _touch_history_file() -> Optional[Path]:
    """Ensure the REPL history file exists."""
    hist = Path.home() / ".history"
    try:
        hist.touch(exist_ok=True)
        return hist
    except Exception:
        return None


def _mark_file(file_path: Path) -> bool:
    """Hide a file on Windows (cosmetic hardening)."""
    try:
        _windows_hide(file_path)
        return True
    except Exception as e:
        print_line(
            colorize(
                f"[WARNING] Failed to mark file as accessed: {e}", "yellow")
        )
        return False


def boot_sequence() -> BootState:
    # ---------- console + env ----------
    _step("Enable ANSI sequences", enable_windows_vt)
    _step(
        f"Detect environment: {platform.system()} {platform.release()} / Python {platform.python_version()}",
        lambda: None,
    )
    _step("Privilege check (admin/root)", lambda: _is_admin_user())

    # ---------- config ----------
    config = _step("Load configuration", validate_or_create_config)

    # Export keystore settings
    from core.db.config import keystore_env_from_config

    def _export_env_from_config():
        env = keystore_env_from_config()
        kf = env.get("KEYSTORE_KEYFILE")
        if kf:
            kf_path = Path(kf)
            if not kf_path.is_absolute():
                kf_path = (config.workspace_path / kf_path).resolve()
            if not kf_path.exists():
                kf_path.parent.mkdir(parents=True, exist_ok=True)
                kf_path.write_bytes(os.urandom(32))
                try:
                    os.chmod(kf_path, 0o600)
                except Exception:
                    pass
            env["KEYSTORE_KEYFILE"] = str(kf_path)
        for k, v in env.items():
            os.environ[k] = v

    _step("Export keystore settings", _export_env_from_config)

    # ---------- workspace ----------
    root = _step(
        "Open secure workspace",
        lambda: setup_secure_workspace(
            getattr(config, "workspace_override", None)),
    )
    set_terminal_title(f"WS: {root.name}")

    _step(
        "Verify hardening marker (.hardened) or first-run",
        lambda: (root / ".hardened").exists() or None,
    )
    _step("Check TEMP/TMP scoped to workspace", lambda: _temp_scoped_to(root))

    # Only re-mark workspace files once (skip on subsequent boots)
    def _mark_workspace_files():
        if not (root / ".marked").exists():
            for f in os.listdir(root):
                _mark_file(root / f)
            (root / ".marked").touch()
    # run async
    # ---------- logging ----------
    logger = _step(
        "Initialize logger",
        lambda: init_logger("lunar", logfile=getattr(
            config, "log_file_path", None)),
    )

    # ---------- database prep ----------
    def _db_bootstrap():
        initialize_database()
        import_existing_workspaces()
        validate_catalog()

    # ---------- parallel section ----------
    with ThreadPoolExecutor(max_workers=4) as pool:
        sysinfo_future = pool.submit(lambda: get_sysinfo(minimal=True))
        mark_future = pool.submit(_mark_workspace_files)
        db_future = pool.submit(_db_bootstrap)

        pkg_name = getattr(config, "commands_package", "plugins")
        _step(f"Locate commands package '{pkg_name}'",
              lambda: __import__(pkg_name))
        _load_cmds()
        loaded_count = _step("Load command definitions",
                             lambda: len(REGISTRY.all()))  # sync

        _step("Warm command names for completion", lambda: REGISTRY.names())
        _step("Collect category descriptions", lambda: REGISTRY.categories())

        if getattr(config, "sync_db_on_start", True):
            _step("Sync command registry to DB", sync_registry_to_database)
        else:
            _step("Skip DB sync (config)", lambda: None)

        # finalize parallel work
        _step("Initialize catalog database", db_future.result)
        _step("Mark workspace files", mark_future.result)
        sysinfo = _step("Probe system information", sysinfo_future.result)

    # ---------- diagnostics / niceties ----------
    _step(
        f"PowerShell available: {'yes' if _ps_available() else 'no'}", lambda: None)
    _step("Prepare history file", _touch_history_file)
    _step(
        "Finalize terminal title",
        lambda: set_terminal_title(f"WS: {root.name} • {loaded_count} cmds"),
    )
    _step("Boot complete", lambda: None)

    return BootState(
        root=root,
        logger=logger,
        config=config,
        loaded_count=loaded_count,
        sysinfo=sysinfo,
    )
