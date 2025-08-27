# commands/system/entrypoint.py
from __future__ import annotations

import json
import re
from typing import Optional, Iterable, Any

from core.commands import command
from core.ui import print_table, print_line
from .kernel import Kernel


def _to_list(obj: Any) -> list:
    """PowerShell ConvertTo-Json returns dict for single object; normalize to list."""
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]


# ---------- cmd.exec ----------
@command(
    name="cmd.exec",
    description="Run a raw cmd.exe command.",
    example='cmd.exec "dir" timeout=5',
    category="system",
    aliases=["cmd"],
)
def cmd_exec(
    *text: str,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    encoding: str = "utf-8",
) -> str:
    k = Kernel()
    command = " ".join(text)
    res = k.run_cmd(
        command or "echo No command provided",
        timeout=timeout,
        cwd=cwd,
        encoding=encoding,
    )
    return res.stdout or (res.stderr or f"exit={res.returncode}")


# ---------- ps.exec ----------
@command(
    name="ps.exec",
    description="Run a PowerShell command (Windows PowerShell or PowerShell 7+).",
    example="ps.exec Get-Process -First 3",
    category="system",
    aliases=["ps"],
)
def ps_exec(
    *text: str,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    encoding: str = "utf-8",
    no_profile: bool = True,
    bypass_policy: bool = True,
    sta: bool = False,
) -> str:
    k = Kernel()
    command = " ".join(text)
    res = k.run_powershell(
        command or "Write-Output 'No command provided'",
        timeout=timeout,
        cwd=cwd,
        encoding=encoding,
        no_profile=no_profile,
        bypass_policy=bypass_policy,
        sta=sta,
    )
    return res.stdout or (res.stderr or f"exit={res.returncode}")


# ---------- system.whoami ----------
@command(
    name="system.whoami",
    description="Show current user, groups, and privileges (whoami /all).",
    example="system.whoami",
    category="system",
    aliases=["whoami"],
)
def system_whoami() -> str:
    k = Kernel()
    res = k.run_cmd(["whoami", "/all"])
    return res.stdout or (res.stderr or f"exit={res.returncode}")


# ---------- process.list ----------
@command(
    name="process.list",
    description="List processes (Name, Id, CPU, WS).",
    example="process.list top=10",
    category="system",
    aliases=["procs", "processes"]
)
def process_list(top: int = 0) -> None:
    """Print a table of processes sorted by CPU."""
    k = Kernel()
    parts = [
        "Get-Process",
        "| Select-Object Name,Id,CPU,WS,StartTime -ErrorAction SilentlyContinue",
        "| Sort-Object -Property CPU -Descending",
    ]
    if top and int(top) > 0:
        parts.append(f"| Select-Object -First {int(top)}")
    parts.append("| ConvertTo-Json -Depth 3")
    res = k.run_powershell(" ".join(parts))
    if not res.ok:
        print_line(res.stderr or "Get-Process failed")
        return None

    try:
        data = _to_list(json.loads(res.stdout) if res.stdout.strip() else [])
    except Exception as exc:
        print_line(f"JSON parse error: {exc}")
        return None

    rows = []
    for p in data:
        name = p.get("Name", "")
        pid = p.get("Id", "")
        cpu = p.get("CPU", 0) or 0
        ws_mb = round((p.get("WS", 0) or 0) / (1024 * 1024), 1)
        start = p.get("StartTime", "")
        rows.append([pid, name, f"{cpu:.1f}", f"{ws_mb:.1f} MB", start])

    print_table(rows, headers=["PID", "Name", "CPU (s)", "Working Set", "StartTime"])
    return None


# ---------- service.list ----------
@command(
    name="service.list",
    description="List Windows services (Name, DisplayName, Status, StartType).",
    example="service.list only_running=true name_like=win",
    category="system",
    aliases=["services"]
)
def service_list(only_running: bool = False, name_like: str = "") -> None:
    """Print a table of services, optionally filtered."""
    k = Kernel()
    filt = ""
    if only_running:
        filt += " | Where-Object {$_.Status -eq 'Running'}"
    if name_like:
        filt += (
            f" | Where-Object {{$_.Name -like '*{name_like}*' -or "
            f"$_.DisplayName -like '*{name_like}*'}}"
        )
    ps = (
        "Get-Service"
        + filt
        + " | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Depth 3"
    )
    res = k.run_powershell(ps)
    if not res.ok:
        print_line(res.stderr or "Get-Service failed")
        return None

    try:
        data = _to_list(json.loads(res.stdout) if res.stdout.strip() else [])
    except Exception as exc:
        print_line(f"JSON parse error: {exc}")
        return None

    rows = [
        [s.get("Name", ""), s.get("DisplayName", ""), s.get("Status", ""), s.get("StartType", "")]
        for s in data
    ]
    print_table(rows, headers=["Name", "Display Name", "Status", "StartType"])
    return None


# ---------- network.info ----------
@command(
    name="network.info",
    description="ipconfig /all, route print, arp -a, netstat -ano, DNS resolvers.",
    example="network.info with_netstat=true with_resolvers=true",
    category="system",
    aliases=["netinfo"]
)
def network_info(with_netstat: bool = True, with_resolvers: bool = True) -> None:
    """Print concise network tables (DNS, ARP, and optional sockets)."""
    k = Kernel()

    # ---- DNS resolvers via PowerShell (structured) ----
    if with_resolvers:
        ps = (
            "Get-DnsClientServerAddress | "
            "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Depth 4"
        )
        dns = k.run_powershell(ps)
        if dns.ok and dns.stdout.strip():
            try:
                dns_data = _to_list(json.loads(dns.stdout))
            except Exception:
                dns_data = []
        else:
            dns_data = []

        if dns_data:
            rows = []
            for it in dns_data:
                alias = it.get("InterfaceAlias", "")
                servers = it.get("ServerAddresses") or []
                rows.append([alias, ", ".join(servers)])
            print_line("### DNS Resolvers")
            print_table(rows, headers=["Interface", "Servers"])
        else:
            print_line("### DNS Resolvers\n(no data)")

    # ---- ARP table (parse 'arp -a') ----
    arp = k.run_cmd(["arp", "-a"])
    print_line("\n### ARP Cache")
    if arp.ok and arp.stdout:
        rows = []
        # lines like: "  192.168.1.1          00-11-22-33-44-55     dynamic"
        for line in arp.stdout.splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})\s+(\w+)", line)
            if m:
                rows.append([m.group(1), m.group(2), m.group(3)])
        if rows:
            print_table(rows, headers=["IP Address", "MAC Address", "Type"])
        else:
            print_line("(no parsable entries)")
    else:
        print_line(arp.stderr or "(failed to retrieve ARP)")

    # ---- Optional: brief sockets view from netstat ----
    if with_netstat:
        ns = k.run_cmd(["netstat", "-ano"])
        print_line("\n### Netstat (LISTENING, first 30)")
        if ns.ok and ns.stdout:
            rows = []
            count = 0
            for line in ns.stdout.splitlines():
                # Typical TCP line: TCP    0.0.0.0:135   0.0.0.0:0   LISTENING   1234
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() in ("TCP", "UDP"):
                    proto = parts[0].upper()
                    local = parts[1]
                    remote = parts[2] if proto == "TCP" else ""
                    state = parts[3] if proto == "TCP" else ""
                    pid = parts[4] if proto == "TCP" else (parts[3] if len(parts) >= 4 else "")
                    if state.upper() == "LISTENING" or proto == "UDP":
                        rows.append([proto, local, remote, state or "-", pid])
                        count += 1
                        if count >= 30:
                            break
            if rows:
                print_table(rows, headers=["Proto", "Local", "Remote", "State", "PID"])
            else:
                print_line("(no listening entries found)")
        else:
            print_line(ns.stderr or "(failed to retrieve netstat)")

    # ---- ipconfig / route (leave as raw summaries for now) ----
    ipcfg = k.run_cmd(["ipconfig", "/all"])
    if ipcfg.ok and ipcfg.stdout:
        print_line("\n### ipconfig /all (truncated)")
        print_line("\n".join(ipcfg.stdout.splitlines()[:40]) + "\n...")

    route = k.run_cmd(["route", "print"])
    if route.ok and route.stdout:
        print_line("\n### route print (truncated)")
        print_line("\n".join(route.stdout.splitlines()[:40]) + "\n...")

    return None


# ---------- system.uptime ----------
@command(
    name="system.uptime",
    description="Report system uptime and last boot time (via CIM).",
    example="system.uptime",
    category="system",
    aliases=["uptime"]
)
def system_uptime() -> str:
    k = Kernel()
    ps = (
        "(Get-CimInstance Win32_OperatingSystem) | "
        "Select-Object LastBootUpTime, LocalDateTime | ConvertTo-Json -Depth 3"
    )
    res = k.run_powershell(ps)
    if not res.ok:
        return res.stderr or "CIM query failed"
    try:
        data = json.loads(res.stdout)
        return json.dumps(data, indent=2)
    except Exception as exc:
        return f"JSON parse error: {exc}"


