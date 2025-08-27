# commands/system/netinfo.py
from __future__ import annotations

from typing import Optional

from .kernel import Kernel

NAME = "network.info"
DESCRIPTION = "Collect common network diagnostics: ipconfig, route, arp, netstat."
ARGS = [
    {"name": "with_netstat", "type": "bool", "required": False, "default": True},
    {"name": "with_resolvers", "type": "bool", "required": False, "default": True},
]


def run(
    kernel: Kernel,
    *,
    with_netstat: bool = True,
    with_resolvers: bool = True,
) -> dict:
    parts = {}

    ipcfg = kernel.run_cmd(["ipconfig", "/all"])
    parts["ipconfig"] = ipcfg.stdout if ipcfg.ok else ipcfg.stderr

    route = kernel.run_cmd(["route", "print"])
    parts["route"] = route.stdout if route.ok else route.stderr

    arp = kernel.run_cmd(["arp", "-a"])
    parts["arp"] = arp.stdout if arp.ok else arp.stderr

    if with_netstat:
        ns = kernel.run_cmd(["netstat", "-ano"])
        parts["netstat"] = ns.stdout if ns.ok else ns.stderr

    if with_resolvers:
        psq = r"Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Depth 3"
        dns = kernel.run_powershell(psq)
        parts["dns_servers"] = dns.stdout if dns.ok else dns.stderr

    ok = ipcfg.ok and route.ok and arp.ok and (not with_netstat or ns.ok)
    return {
        "success": ok,
        "data": parts,
        "error": None if ok else "One or more network queries failed.",
    }
