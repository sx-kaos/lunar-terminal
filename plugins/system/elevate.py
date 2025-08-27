# commands/system/elevate.py
from __future__ import annotations

from .kernel import Kernel

NAME = "security.elevate"
DESCRIPTION = "Report admin status and attempt to enable a privilege."
ARGS = [
    {"name": "privilege", "type": "str", "required": False, "default": "SeDebugPrivilege"},
]


def run(kernel: Kernel, *, privilege: str = "SeDebugPrivilege") -> dict:
    is_admin = Kernel.is_admin()
    ok, msg = Kernel.enable_privilege(privilege)
    return {
        "success": ok or is_admin,
        "data": {"is_admin": is_admin, "privilege": privilege, "result": msg},
        "error": None if (ok or is_admin) else msg,
    }
