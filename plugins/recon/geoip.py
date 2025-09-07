# commands/recon/geoip.py
from __future__ import annotations

"""
GeoIP lookup via ip-api.com (free, no key).

Notes:
- The free endpoint is HTTP; keep a conservative timeout.
- We keep the response compact and normalized.
"""

import json
import socket
import urllib.request
import ipaddress
from typing import Dict, Any


USER_AGENT = "lunar-terminal/2.0 (+https://local)"


def _to_ip(ip_or_hostname: str) -> str:
    """
    Resolve an input string to a concrete IPv4 address (A record).

    Strategy:
        - If ip_or_hostname parses as an IP (v4/v6), return it as-is.
        - Else resolve with gethostbyname (IPv4 only for the free API).
    """
    try:
        # Accept both IPv4 and IPv6 literals
        ipaddress.ip_address(ip_or_hostname)
        return ip_or_hostname
    except ValueError:
        # gethostbyname is IPv4-only and matches the free API expectation
        return socket.gethostbyname(ip_or_hostname)


def geoip_lookup(ip_or_hostname: str, timeout_seconds: float = 6.0) -> Dict[str, Any]:
    """
    Fetch compact GeoIP info from ip-api.com.

    Args:
        ip_or_hostname: IP or hostname to lookup.
        timeout_seconds: Network timeout for the HTTP request.

    Returns:
        Dict with normalized keys or an {'error': str, 'query': str} on failure.
    """
    ip = _to_ip(ip_or_hostname)
    url = (
        "http://ip-api.com/json/"
        f"{ip}?fields=status,message,continent,country,regionName,city,lat,lon,isp,org,as,"
        "mobile,proxy,hosting,query"
    )
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))

    if payload.get("status") != "success":
        return {"error": payload.get("message", "lookup failed"), "query": ip}

    return {
        "ip": payload.get("query"),
        "continent": payload.get("continent"),
        "country": payload.get("country"),
        "region": payload.get("regionName"),
        "city": payload.get("city"),
        "lat": payload.get("lat"),
        "lon": payload.get("lon"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "asn": payload.get("as"),
        "mobile": payload.get("mobile"),
        "proxy": payload.get("proxy"),
        "hosting": payload.get("hosting"),
    }
