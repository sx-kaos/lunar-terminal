# commands/system/services.py
from __future__ import annotations

import json
from typing import Optional

from .kernel import Kernel

NAME = "service.list"
DESCRIPTION = "List Windows services (Name, DisplayName, Status, StartType)."
ARGS = [
    {"name": "only_running", "type": "bool", "required": False, "default": False},
    {"name": "name_like", "type": "str", "required": False, "default": ""},
]


def run(kernel: Kernel, *, only_running: bool = False, name_like: str = "") -> dict:
    filter_block = ""
    if only_running:
        filter_block += " | Where-Object {$_.Status -eq 'Running'}"
    if name_like:
        # Simple wildcard match against Name or DisplayName
        filter_block += (
            f" | Where-Object {{$_.Name -like '*{name_like}*' -or "
            f"$_.DisplayName -like '*{name_like}*'}}"
        )

    ps = (
        "Get-Service"
        + filter_block
        + " | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Depth 3"
    )

    res = kernel.run_powershell(ps)
    if not res.ok:
        return {"success": False, "data": None, "error": res.stderr or "Get-Service failed"}

    try:
        data = json.loads(res.stdout) if res.stdout.strip() else []
    except Exception as exc:
        return {"success": False, "data": None, "error": f"JSON parse error: {exc}"}

    return {"success": True, "data": data, "error": None}
