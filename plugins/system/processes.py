# commands/system/processes.py
from __future__ import annotations

import json
from .kernel import Kernel

NAME = "process.list"
DESCRIPTION = "List processes with basic metrics (Name, Id, CPU, WS)."
ARGS = [{"name": "top", "type": "int", "required": False, "default": 0}]


def run(kernel: Kernel, *, top: int = 0) -> dict:
    parts = [
        "Get-Process",
        "| Select-Object Name,Id,CPU,WS,StartTime -ErrorAction SilentlyContinue",
        "| Sort-Object -Property CPU -Descending",
    ]
    if top and int(top) > 0:
        parts.append(f"| Select-Object -First {int(top)}")
    parts.append("| ConvertTo-Json -Depth 3")
    ps = " ".join(parts)

    res = kernel.run_powershell(ps)
    if not res.ok:
        return {"success": False, "data": None, "error": res.stderr or "Get-Process failed"}

    try:
        data = json.loads(res.stdout) if res.stdout.strip() else []
    except Exception as exc:
        return {"success": False, "data": None, "error": f"JSON parse error: {exc}"}

    return {"success": True, "data": data, "error": None}
