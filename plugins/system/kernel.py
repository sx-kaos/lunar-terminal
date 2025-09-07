# commands/system/kernel.py
"""
Windows command/WinAPI interface.

This module provides a small, well-typed facade for:
- Running cmd.exe and PowerShell commands.
- Common WinAPI helpers via ctypes.

Designed for Windows 11 with only Python stdlib.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple, Union

# ---- Public result type -----------------------------------------------------


@dataclass(slots=True)
class CommandResult:
    """Normalized result for shell execution."""
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    duration_sec: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# ---- Kernel -----------------------------------------------------------------


class Kernel:
    """
    Thin interface to run cmd/PowerShell and a few WinAPI helpers.

    Notes:
        - Avoids shell injection by passing argument lists to subprocess.
        - Uses CREATE_NO_WINDOW to keep executions quiet in consoles/GUI.
        - PowerShell selection prefers Windows PowerShell, then pwsh.
    """

    # Creation flag to prevent flashing a console window in GUI context.
    _CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

    def __init__(self, powershell: Optional[str] = None) -> None:
        """
        Args:
            powershell: Optional explicit path/exe name. If None, autodetects.
        """
        self._ps = powershell or self._detect_powershell()

    # ---- Shell runners ------------------------------------------------------

    def run(
        self,
        command: Union[str, Sequence[str]],
        *,
        shell: str = "cmd",
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
    ) -> CommandResult:
        """
        Run a command via cmd or PowerShell and return a normalized result.

        Args:
            command: String or list of arguments. If string, passed to the
                chosen shell's -Command (PowerShell) or /C (cmd.exe).
            shell: "cmd" or "powershell".
            timeout: Seconds before terminating.
            env: Environment overrides.
            cwd: Working directory.
            encoding: Decode stdout/stderr using this encoding.

        Returns:
            CommandResult
        """
        if shell not in {"cmd", "powershell"}:
            raise ValueError('shell must be "cmd" or "powershell"')

        if shell == "cmd":
            return self.run_cmd(command, timeout=timeout, env=env, cwd=cwd,
                                encoding=encoding)
        return self.run_powershell(command, timeout=timeout, env=env, cwd=cwd,
                                   encoding=encoding)

    def run_cmd(
        self,
        command: Union[str, Sequence[str]],
        *,
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
    ) -> CommandResult:
        """
        Run a command with cmd.exe /C.

        Examples:
            run_cmd("dir")
            run_cmd(["ipconfig", "/all"])
        """
        if isinstance(command, str):
            args: List[str] = ["cmd.exe", "/C", command]
        else:
            # For arg lists, call directly (safer). No /C needed.
            args = list(command)

        return self._exec(args, timeout=timeout, env=env, cwd=cwd,
                          encoding=encoding)

    def run_powershell(
        self,
        command: Union[str, Sequence[str]],
        *,
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
        no_profile: bool = True,
        bypass_policy: bool = True,
        sta: bool = False,
    ) -> CommandResult:
        """
        Run a command/script in PowerShell.

        If `command` is a string, it is passed using -Command.
        If it's a list/sequence, the first element is treated as a script or
        executable; pass PS-style arguments yourself.

        Args:
            no_profile: Use -NoProfile for deterministic runs.
            bypass_policy: Use -ExecutionPolicy Bypass.
            sta: Use -STA if needed for certain COM operations.
        """
        ps = self._ps
        if not ps:
            return CommandResult("", "PowerShell not found.", 1, False, 0.0)

        ps_flags: List[str] = [ps]
        if no_profile:
            ps_flags.append("-NoProfile")
        if bypass_policy:
            ps_flags.extend(["-ExecutionPolicy", "Bypass"])
        if sta:
            ps_flags.append("-STA")

        if isinstance(command, str):
            args = [*ps_flags, "-Command", command]
        else:
            # Treat as direct arg list after the PS executable/flags.
            args = [*ps_flags, *command]

        return self._exec(args, timeout=timeout, env=env, cwd=cwd,
                          encoding=encoding)

    # ---- WinAPI helpers (ctypes) -------------------------------------------

    @staticmethod
    def is_admin() -> bool:
        """Return True if the current process has admin rights."""
        if os.name != "nt":
            return False
        try:
            import ctypes  # local import keeps module lightweight at top
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def get_last_error_message(code: Optional[int] = None) -> str:
        """Return the Windows error message string for GetLastError or a code."""
        if os.name != "nt":
            return ""
        import ctypes
        from ctypes import wintypes

        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

        if code is None:
            code = ctypes.GetLastError()

        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            wintypes.DWORD(code),
            0,
            buf,
            len(buf),
            None,
        )
        return buf.value.strip() if n else f"WinError {code}"

    @staticmethod
    def get_windows_version() -> Tuple[int, int, int]:
        """
        Return (major, minor, build). For Windows 11, expect (10, 0, build>=22000).
        """
        # platform.release() is unreliable for exact build; use sys.getwindowsversion
        if os.name != "nt":
            return (0, 0, 0)
        winver = sys.getwindowsversion()  # type: ignore[attr-defined]
        return (winver.major, winver.minor, winver.build)

    # ---- Internals ----------------------------------------------------------

    def _exec(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[float],
        env: Optional[dict],
        cwd: Optional[str],
        encoding: str,
    ) -> CommandResult:
        start = time.perf_counter()
        try:
            completed = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env={**os.environ, **(env or {})} if env else None,
                cwd=cwd,
                creationflags=self._CREATE_NO_WINDOW,
                text=False,  # capture bytes; decode ourselves
            )
            duration = time.perf_counter() - start
            stdout = completed.stdout.decode(encoding, errors="replace")
            stderr = completed.stderr.decode(encoding, errors="replace")
            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                returncode=completed.returncode,
                timed_out=False,
                duration_sec=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start
            stdout = (exc.stdout or b"").decode(encoding, errors="replace")
            stderr = (exc.stderr or b"").decode(encoding, errors="replace")
            return CommandResult(
                stdout=stdout,
                stderr=stderr or "Process timed out.",
                returncode=1,
                timed_out=True,
                duration_sec=duration,
            )
        except FileNotFoundError as exc:
            duration = time.perf_counter() - start
            return CommandResult(
                stdout="",
                stderr=str(exc),
                returncode=1,
                timed_out=False,
                duration_sec=duration,
            )

    @staticmethod
    def _detect_powershell() -> Optional[str]:
        """
        Prefer Windows PowerShell (powershell.exe). If not found, try pwsh (PS7+).
        """
        candidates = ["powershell.exe", "pwsh.exe"]
        for exe in candidates:
            path = Kernel._which(exe)
            if path:
                return path
        return None

    @staticmethod
    def _which(executable: str) -> Optional[str]:
        """
        A minimal cross-version 'which' for Windows.
        """
        paths = os.environ.get("PATH", "").split(os.pathsep)
        exts = os.environ.get("PATHEXT", ".EXE;.BAT;.CMD").split(";")
        for p in paths:
            full = os.path.join(p, executable)
            if os.path.isfile(full):
                return full
            # Add PATHEXT variants if not already with an extension
            if "." not in os.path.basename(executable):
                for ext in exts:
                    full_ext = full + ext
                    if os.path.isfile(full_ext):
                        return full_ext
        return None
