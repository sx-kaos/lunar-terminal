# commands/system/uptime.py
from __future__ import annotations

import json
from datetime import datetime, timezone

from .kernel import Kernel

NAME = "system.uptime"
DESCRIPTION = "Report system uptime and last boot time (via CIM)."


def run(kernel: Kernel) -> dict:
    # Prefer CIM for accurate boot time
    ps = (
        "(Get-CimInstance Win32_OperatingSystem) | "
        "Select-Object LastBootUpTime, LocalDateTime | ConvertTo-Json -Depth 3"
    )
    res = kernel.run_powershell(ps)
    if not res.ok:
        return {"success": False, "data": None, "error": res.stderr or "CIM query failed"}

    try:
        info = json.loads(res.stdout)
        boot = info.get("LastBootUpTime")
        now = info.get("LocalDateTime")
        data = {"last_boot": boot, "local_time": now}
    except Exception as exc:
        return {"success": False, "data": None, "error": f"JSON parse error: {exc}"}

    return {"success": True, "data": data, "error": None}
