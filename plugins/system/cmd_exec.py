# commands/system/cmd_exec.py
from __future__ import annotations

from typing import Optional

from .kernel import Kernel

NAME = "cmd.exec"
DESCRIPTION = "Run a raw cmd.exe command string or argument list."
ARGS = [
    {"name": "command", "type": "str|list", "required": True},
    {"name": "timeout", "type": "float", "required": False, "default": None},
    {"name": "cwd", "type": "str", "required": False, "default": None},
    {"name": "encoding", "type": "str", "required": False, "default": "utf-8"},
]


def run(
    kernel: Kernel,
    *,
    command,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    encoding: str = "utf-8",
) -> dict:
    res = kernel.run_cmd(command, timeout=timeout, cwd=cwd, encoding=encoding)
    return {
        "success": res.ok,
        "data": {
            "stdout": res.stdout,
            "stderr": res.stderr,
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "duration_sec": res.duration_sec,
        },
        "error": None if res.ok else (res.stderr or "cmd.exe failed"),
    }
