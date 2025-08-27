# commands/recon/iana.py
from __future__ import annotations

"""
WHOIS helpers:
- Query IANA, parse compact fields, follow referral WHOIS if present.

Parsing is tolerant: we collect 'key: value' pairs case-insensitively
and emit concise summaries for display.
"""

import re
import socket
from typing import Dict, List, Optional, Tuple


# -------------------- Parsing helpers --------------------

LINE_KEY_VALUE = re.compile(r"^\s*([^:]+)\s*:\s*(.*)\s*$")


def _parse_key_values(raw_text: str) -> Dict[str, List[str]]:
    """Parse 'key: value' lines into dict-of-lists with lowercase keys."""
    result: Dict[str, List[str]] = {}
    for line in raw_text.splitlines():
        match = LINE_KEY_VALUE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        result.setdefault(key, []).append(value)
    return result


def _first_value(dct: Dict[str, List[str]], key: str) -> Optional[str]:
    vals = dct.get(key.lower())
    return vals[0] if vals else None


def _all_values(dct: Dict[str, List[str]], key: str) -> List[str]:
    return dct.get(key.lower(), [])


def _clean_nameserver(value: str) -> str:
    """
    IANA often prints nameserver with glue IPs:
        "A.GTLD-SERVERS.NET 192.5.6.30 2001:503:..."
    Keep only the first token (the hostname).
    """
    parts = value.split()
    return parts[0] if parts else value


# -------------------- Public tidy extractors --------------------

def tidy_iana(raw_text: str) -> Dict[str, object]:
    """
    Extract a concise snapshot from IANA WHOIS text.

    Returns:
        {
          "summary": list[tuple[str, str]],
          "nameservers": list[str],
          "referral": str | None
        }
    """
    kv = _parse_key_values(raw_text)
    summary: List[Tuple[str, str]] = []

    domain = _first_value(kv, "domain") or _first_value(kv, "tld") or ""
    org = _first_value(kv, "organisation") or _first_value(kv, "organization") or ""
    whois_server = _first_value(kv, "refer") or _first_value(kv, "whois") or ""
    created = _first_value(kv, "created") or ""
    changed = _first_value(kv, "changed") or ""
    statuses = _all_values(kv, "status")

    if domain:
        summary.append(("Domain/TLD", domain))
    if org:
        summary.append(("Registry", org))
    if whois_server:
        summary.append(("Referral WHOIS", whois_server))
    if created:
        summary.append(("Created", created))
    if changed:
        summary.append(("Changed", changed))
    if statuses:
        summary.append(("Status", ", ".join(statuses)))

    nameservers = [_clean_nameserver(v) for v in _all_values(kv, "nserver")]

    return {
        "summary": summary,
        "nameservers": nameservers,
        "referral": whois_server or None,
    }


def tidy_referral(raw_text: str) -> Dict[str, object]:
    """
    Extract a concise snapshot from a referred WHOIS (e.g., registry/registrar).

    Returns:
        {
          "summary": list[tuple[str, str]],
          "statuses": list[str],
          "nameservers": list[str]
        }
    """
    kv = _parse_key_values(raw_text)

    registrar = _first_value(kv, "registrar") or _first_value(kv, "sponsoring registrar") or ""
    r_whois = _first_value(kv, "registrar whois server") or _first_value(kv, "whois server") or ""
    r_url = _first_value(kv, "registrar url") or _first_value(kv, "url") or ""
    updated = _first_value(kv, "updated date") or _first_value(kv, "last updated") or ""
    created = _first_value(kv, "creation date") or _first_value(kv, "created on") or ""
    expires = _first_value(kv, "registry expiry date") or _first_value(kv, "expiry date") or ""
    dnssec = _first_value(kv, "dnssec") or ""

    summary: List[Tuple[str, str]] = []
    if registrar:
        summary.append(("Registrar", registrar))
    if r_whois:
        summary.append(("Registrar WHOIS", r_whois))
    if r_url:
        summary.append(("Registrar URL", r_url))
    if created:
        summary.append(("Created", created))
    if updated:
        summary.append(("Updated", updated))
    if expires:
        summary.append(("Expires", expires))
    if dnssec:
        summary.append(("DNSSEC", dnssec))

    statuses = _all_values(kv, "domain status")
    nameservers = _all_values(kv, "name server")

    return {
        "summary": summary,
        "statuses": statuses,
        "nameservers": nameservers,
    }


# -------------------- Network helpers --------------------

def _recv_all(sock: socket.socket, bufsize: int = 4096) -> str:
    """Read until EOF and decode with replacement to avoid crashes."""
    chunks: List[bytes] = []
    while True:
        data = sock.recv(bufsize)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def whois_query(server: str, query: str, *, timeout_seconds: float = 8.0) -> str:
    """Send a WHOIS query to server:43 and return the raw text."""
    with socket.create_connection((server, 43), timeout=timeout_seconds) as sock:
        sock.sendall((query + "\r\n").encode("utf-8"))
        return _recv_all(sock)


def iana_lookup(target: str, *, timeout_seconds: float = 8.0) -> Tuple[str, Optional[str]]:
    """
    Query IANA and return (iana_text, referral_server).
    """
    iana_text = whois_query("whois.iana.org", target, timeout_seconds=timeout_seconds)
    kv = _parse_key_values(iana_text)
    referral = _first_value(kv, "refer") or _first_value(kv, "whois")
    return iana_text, referral


def whois_follow(target: str, *, timeout_seconds: float = 8.0) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Query IANA and, if a referral server is provided, query it too.

    Returns:
        (iana_text, referral_server, referral_text_or_none)
    """
    iana_text, referral = iana_lookup(target, timeout_seconds=timeout_seconds)
    referral_text: Optional[str] = None
    if referral:
        try:
            referral_text = whois_query(referral, target, timeout_seconds=timeout_seconds)
        except Exception:
            referral_text = None
    return iana_text, referral, referral_text
