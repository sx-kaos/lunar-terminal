# commands/system/whoami.py
from __future__ import annotations

from .kernel import Kernel

NAME = "system.whoami"
DESCRIPTION = "Show current user, groups, and privileges (whoami /all)."


def run(kernel: Kernel) -> dict:
    res = kernel.run_cmd(["whoami", "/all"])
    return {
        "success": res.ok,
        "data": {"text": res.stdout},
        "error": None if res.ok else (res.stderr or "whoami failed"),
    }
