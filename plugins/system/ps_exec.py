# commands/system/ps_exec.py
from __future__ import annotations

from typing import Optional

from .kernel import Kernel

NAME = "ps.exec"
DESCRIPTION = "Run a PowerShell command (Windows PowerShell or PowerShell 7+)."
ARGS = [
    {"name": "command", "type": "str|list", "required": True},
    {"name": "timeout", "type": "float", "required": False, "default": None},
    {"name": "cwd", "type": "str", "required": False, "default": None},
    {"name": "encoding", "type": "str", "required": False, "default": "utf-8"},
    {"name": "no_profile", "type": "bool", "required": False, "default": True},
    {"name": "bypass_policy", "type": "bool", "required": False, "default": True},
    {"name": "sta", "type": "bool", "required": False, "default": False},
]


def run(
    kernel: Kernel,
    *,
    command,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    encoding: str = "utf-8",
    no_profile: bool = True,
    bypass_policy: bool = True,
    sta: bool = False,
) -> dict:
    res = kernel.run_powershell(
        command,
        timeout=timeout,
        cwd=cwd,
        encoding=encoding,
        no_profile=no_profile,
        bypass_policy=bypass_policy,
        sta=sta,
    )
    return {
        "success": res.ok,
        "data": {
            "stdout": res.stdout,
            "stderr": res.stderr,
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "duration_sec": res.duration_sec,
        },
        "error": None if res.ok else (res.stderr or "PowerShell failed"),
    }
