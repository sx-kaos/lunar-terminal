# commands/recon/dnsutils.py
from __future__ import annotations

"""
DNS helpers (stdlib only).

Provides:
    - resolve_host_addresses: A/AAAA lookup for a hostname
    - reverse_dns_lookup: PTR lookup for an IP address
"""

import socket
from typing import List


def resolve_host_addresses(hostname: str, *, family: int | None = None) -> List[str]:
    """
    Resolve A/AAAA addresses for a hostname using stdlib.

    Args:
        hostname: Domain name to resolve.
        family: Optional socket family (e.g., socket.AF_INET, socket.AF_INET6).
                If None, both families are considered.

    Returns:
        Sorted list of unique IP addresses as strings.
    """
    # getaddrinfo(None) service -> resolve only
    infos = socket.getaddrinfo(hostname, None, family=family or 0, type=0, proto=0, flags=0)
    addresses = sorted({info[4][0] for info in infos})
    return addresses


def reverse_dns_lookup(ip_address: str) -> str:
    """
    Perform a PTR (reverse DNS) lookup for an IPv4/IPv6 address.

    Args:
        ip_address: The IP address as a string.

    Returns:
        Primary hostname returned by PTR.

    Raises:
        socket.herror, socket.gaierror on resolution failures.
    """
    hostname, _aliases, _addrs = socket.gethostbyaddr(ip_address)
    return hostname
