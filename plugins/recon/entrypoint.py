# commands/recon/entrypoint.py
from __future__ import annotations

"""
Recon command entrypoint:

Commands:
    - iana-whois: IANA WHOIS query with optional referral follow
    - geoip:      ip-api.com (free) compact GeoIP
    - dns:        A/AAAA resolution
    - reversedns: PTR lookup
    - ssl-cert:   Fetch TLS leaf certificate details (subject/issuer/dates/fingerprint)
    - banner-grab:Smart banner grabbing & lightweight service probes
    - dns-records:Query MX/NS/TXT via tiny stdlib DNS client
    - subbrute:   Subdomain brute force with threading & progress
"""

import hashlib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Sequence, Tuple

from core.commands import command, CommandResult
from core.ui import format_table, ProgressBar
from core.security import secure_dir, resolve_in_sandbox
from . import iana, geoip, dnsutils
from .dnsclient import query, QTYPE_MX, QTYPE_NS, QTYPE_TXT


# -------------------- Completers (niceties) --------------------

COMMON_HOSTS: tuple[str, ...] = (
    "example.com",
    "google.com",
    "cloudflare.com",
    "1.1.1.1",
    "8.8.8.8",
)


def _complete_host(*, text: str, argv: Sequence[str], index: int | None):
    """Suggest common hosts/IPs for quick demos."""
    lower = text.lower()
    for host in COMMON_HOSTS:
        if host.lower().startswith(lower):
            yield host


def _complete_ipv4(*, text: str, argv: Sequence[str], index: int | None):
    """Suggest a few well-known resolvers for PTR demos."""
    for host in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        if host.startswith(text):
            yield host


# -------------------- Rendering helpers --------------------

def _table_from_pairs(title: str, pairs: List[Tuple[str, str]]) -> str:
    """Render (key, value) list as a two-column table with a heading."""
    if not pairs:
        return ""
    heading = f"\n{title}\n" + ("-" * len(title))
    table = format_table(rows=pairs, headers=["Field", "Value"])
    return f"{heading}\n{table}"


def _kv_block(title: str, items: List[Tuple[str, str]]) -> str:
    """Simple aligned key/value block."""
    if not items:
        return ""
    heading = f"\n{title}\n" + ("-" * len(title))
    width = max(len(str(k)) for k, _ in items)
    lines = [f"{str(k).ljust(width)} : {v}" for k, v in items]
    return f"{heading}\n" + "\n".join(lines)


# -------------------- Existing commands (unchanged) --------------------

@command(
    name="iana-whois",
    description="Query whois.iana.org for a target (TLD/domain/IP); optionally follow referral.",
    example="iana-whois com follow=true",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_iana_whois(target: str, *, follow: bool = True, timeout: float = 8.0) -> CommandResult:
    try:
        if follow:
            iana_text, referral, referral_text = iana.whois_follow(target, timeout_seconds=timeout)
        else:
            iana_text, referral = iana.iana_lookup(target, timeout_seconds=timeout)
            referral_text = None

        iana_tidy = iana.tidy_iana(iana_text)
        iana_summary = _table_from_pairs(f"IANA WHOIS – {target}", iana_tidy["summary"])  # type: ignore[arg-type]

        nameservers_iana: List[str] = iana_tidy.get("nameservers", [])  # type: ignore[assignment]
        iana_ns = _kv_block("IANA Nameservers", [(str(i + 1), ns.upper()) for i, ns in enumerate(nameservers_iana)])

        referral_block = ""
        if referral:
            if referral_text:
                ref_tidy = iana.tidy_referral(referral_text)
                ref_summary = _table_from_pairs("Registrar WHOIS", ref_tidy["summary"])  # type: ignore[arg-type]

                statuses: List[str] = ref_tidy.get("statuses", [])  # type: ignore[assignment]
                statuses_block = _kv_block(
                    "Domain Status", [(str(i + 1), s) for i, s in enumerate(statuses)]
                )

                nameservers_ref: List[str] = ref_tidy.get("nameservers", [])  # type: ignore[assignment]
                ref_ns_block = _kv_block(
                    "Registrar Nameservers", [(str(i + 1), ns.upper()) for i, ns in enumerate(nameservers_ref)]
                )

                referral_block = f"{ref_summary}{statuses_block}{ref_ns_block}"
            else:
                referral_block = _table_from_pairs(
                    "Registrar WHOIS",
                    [("Server", referral), ("Result", "no response or follow disabled")],
                )

        message = f"{iana_summary}{iana_ns}{referral_block}".strip()
        return CommandResult(ok=True, message=message or "No data.")
    except Exception as exc:
        return CommandResult(ok=False, message=f"[whois] {type(exc).__name__}: {exc}")


@command(
    name="geoip",
    description="GeoIP lookup for an IP/host via ip-api.com (free, no key).",
    example="geoip 1.1.1.1",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_geoip(ip_or_host: str, *, timeout: float = 6.0) -> CommandResult:
    try:
        data = geoip.geoip_lookup(ip_or_host, timeout_seconds=timeout)
        if "error" in data:
            return CommandResult(ok=False, message=f"GeoIP error: {data['error']} ({data.get('query','')})")
        ordered = (
            "ip", "continent", "country", "region", "city", "lat", "lon", "isp", "org", "asn", "mobile", "proxy", "hosting"
        )
        return CommandResult(ok=True, message="\n".join(f"{k}: {data.get(k)}" for k in ordered))
    except Exception as exc:
        return CommandResult(ok=False, message=f"[geoip] {type(exc).__name__}: {exc}")


@command(
    name="dns",
    description="DNS A/AAAA resolution using stdlib.",
    example="dns example.com",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_dns(host: str) -> CommandResult:
    try:
        ips = dnsutils.resolve_host_addresses(host)
        return CommandResult(ok=bool(ips), message="\n".join(ips) if ips else "No A/AAAA records.")
    except Exception as exc:
        return CommandResult(ok=False, message=f"[dns] {type(exc).__name__}: {exc}")


@command(
    name="reversedns",
    description="Reverse DNS (PTR) for an IP address.",
    example="reversedns 1.1.1.1",
    category="recon",
    completers={"pos0": _complete_ipv4},
)
def cmd_reversedns(ip: str) -> CommandResult:
    try:
        hostname = dnsutils.reverse_dns_lookup(ip)
        return CommandResult(ok=True, message=hostname)
    except Exception as exc:
        return CommandResult(ok=False, message=f"[reversedns] {type(exc).__name__}: {exc}")


# -------------------- New: ssl-cert --------------------

@command(
    name="ssl-cert",
    description="Fetch TLS leaf certificate details from host:port (default 443).",
    example="ssl-cert example.com port=443",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_ssl_cert(target_host: str, *, port: int = 443, timeout: float = 6.0) -> CommandResult:
    """
    Connect with SNI and retrieve the peer certificate dictionary.
    Note: Standard library exposes only the leaf certificate in a portable way.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as tls:
                cert_dict = tls.getpeercert()  # parsed dict (portable)
                der_leaf = tls.getpeercert(True)  # bytes for fingerprint
    except Exception as exc:
        return CommandResult(ok=False, message=f"[ssl] {type(exc).__name__}: {exc}")

    # Extract common fields
    subject = " / ".join("=".join(x) for rdn in cert_dict.get("subject", []) for x in rdn)
    issuer = " / ".join("=".join(x) for rdn in cert_dict.get("issuer", []) for x in rdn)
    not_before = cert_dict.get("notBefore", "")
    not_after = cert_dict.get("notAfter", "")

    sha256 = hashlib.sha256(der_leaf).hexdigest().upper()
    fingerprint = ":".join(sha256[i : i + 2] for i in range(0, len(sha256), 2))

    rows = [
        ("Host", f"{target_host}:{port}"),
        ("Subject", subject or "(unknown)"),
        ("Issuer", issuer or "(unknown)"),
        ("Not Before", not_before),
        ("Not After", not_after),
        ("SHA256", fingerprint),
    ]
    return CommandResult(ok=True, message=_table_from_pairs("TLS Certificate (leaf)", rows))


# -------------------- New: banner-grab --------------------

def _probe_http(sock: socket.socket, host: str) -> None:
    try:
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
    except Exception:
        pass


def _read_some(sock: socket.socket, limit: int = 1024) -> bytes:
    try:
        return sock.recv(limit)
    except Exception:
        return b""


@command(
    name="banner-grab",
    description="Connect to a port and attempt simple protocol probes to elicit a banner.",
    example="banner-grab host=scanme.nmap.org ports=22,80,443,25 timeout=2.0",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_banner_grab(*, host: str, ports: str, timeout: float = 2.0, tls: bool = False) -> CommandResult:
    """
    Try to elicit banners from common services; minimal heuristics.
    For HTTPS, either use 'tls=true' or include port 443 and it will be probed with TLS automatically.
    """
    try:
        port_list = sorted({int(p.strip()) for p in ports.split(",") if p.strip()})
        port_list = [p for p in port_list if 0 < p < 65536]
    except Exception:
        return CommandResult(ok=False, message="Invalid 'ports'. Use comma-separated integers.")

    lines: List[str] = []
    for port in port_list:
        try:
            use_tls = tls or port in (443, 8443)
            base_sock = socket.create_connection((host, port), timeout=timeout)
            base_sock.settimeout(timeout)

            if use_tls:
                context = ssl.create_default_context()
                with context.wrap_socket(base_sock, server_hostname=host) as s:
                    _probe_http(s, host)
                    data = _read_some(s)
            else:
                # Protocol-specific nudges
                if port in (80, 8080, 8000):
                    _probe_http(base_sock, host)
                elif port in (25, 587):
                    # SMTP: banner arrives first; then say EHLO
                    data = _read_some(base_sock)
                    try:
                        base_sock.sendall(b"EHLO example.com\r\n")
                    except Exception:
                        pass
                elif port == 21:
                    # FTP banner first
                    pass
                elif port == 143:
                    # IMAP banner first
                    pass
                elif port == 110:
                    # POP3 banner first
                    pass
                elif port == 22:
                    # SSH banner first
                    pass
                # Read
                data = _read_some(base_sock)
                base_sock.close()

            preview = data.decode("utf-8", "replace").replace("\r", "")
            # Keep first line or 200 chars
            first_line = preview.split("\n", 1)[0][:200]
            lines.append(f"{host}:{port} -> {first_line!r}")
        except Exception as exc:
            lines.append(f"{host}:{port} -> error: {exc}")

    ok = any("->" in ln and "error" not in ln for ln in lines)
    header = f"Probed {len(port_list)} port(s) on {host}"
    return CommandResult(ok=ok, message="\n".join([header, *lines]))


# -------------------- New: dns-records (MX/NS/TXT) --------------------

@command(
    name="dns-records",
    description="Query MX/NS/TXT records using a tiny stdlib DNS client (UDP).",
    example="dns-records example.com type=MX server=1.1.1.1",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_dns_records(domain: str, *, type: str = "MX", server: str | None = None, timeout: float = 3.0) -> CommandResult:
    """
    Look up MX/NS/TXT using UDP queries. Defaults to public resolvers if 'server' not provided.
    """
    qtype_map = {"MX": QTYPE_MX, "NS": QTYPE_NS, "TXT": QTYPE_TXT}
    qtype = qtype_map.get(type.upper())
    if not qtype:
        return CommandResult(ok=False, message="Unsupported type. Use MX, NS, or TXT.")

    nameservers = [server] if server else None
    records = query(domain, qtype, nameservers=nameservers, timeout=timeout, tries=2)
    if not records:
        return CommandResult(ok=False, message="No records or query failed.")

    # Normalize output per type
    rows: List[Tuple[str, str]] = []
    for rr in records:
        if qtype == QTYPE_MX and isinstance(rr.get("data"), dict):
            mx = rr["data"]
            rows.append((rr["name"], f"{mx.get('preference')} {mx.get('exchange')}"))
        elif qtype == QTYPE_NS:
            rows.append((rr["name"], str(rr.get("data"))))
        elif qtype == QTYPE_TXT:
            txt_list = rr.get("data") or []
            rows.append((rr["name"], " | ".join(txt_list)))
    return CommandResult(ok=True, message=_table_from_pairs(f"{type.upper()} records for {domain}", rows))


# -------------------- New: subbrute --------------------

def _load_wordlist(source: str) -> List[str]:
    """
    Load subdomain list from:
      - comma-separated inline: "www,mail,api"
      - file path (inside secure workspace)
    """
    if "," in source:
        return [w.strip() for w in source.split(",") if w.strip()]
    path = resolve_in_sandbox(source)
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return [w.strip() for w in text.splitlines() if w.strip() and not w.strip().startswith("#")]


def _try_resolve(fqdn: str, timeout: float) -> Tuple[str, List[str]]:
    try:
        infos = socket.getaddrinfo(fqdn, None)
        ips = sorted({info[4][0] for info in infos})
        return fqdn, ips
    except Exception:
        return fqdn, []


@command(
    name="subbrute",
    description="Brute-force subdomains using a wordlist (file or inline list).",
    example="subbrute example.com wordlist=subs.txt workers=50 timeout=1.0",
    category="recon",
    completers={"pos0": _complete_host},
)
def cmd_subbrute(base_domain: str, *, wordlist: str, workers: int = 50, timeout: float = 1.0) -> CommandResult:
    """
    Resolve <word>.<base_domain> for each entry in the wordlist using a thread pool.
    """
    words = _load_wordlist(wordlist)
    if not words:
        return CommandResult(ok=False, message="Wordlist is empty.")

    found: List[Tuple[str, List[str]]] = []

    with ProgressBar(total_units=len(words), label_text=f"Subdomains {base_domain}") as bar:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            futures = {executor.submit(_try_resolve, f"{w}.{base_domain}", timeout): w for w in words}
            for idx, future in enumerate(as_completed(futures), start=1):
                fqdn, ips = future.result()
                if ips:
                    found.append((fqdn, ips))
                bar.update(idx)

    if not found:
        return CommandResult(ok=False, message="No subdomains found.")

    rows: List[Tuple[str, str]] = [(fqdn, ", ".join(ips)) for fqdn, ips in sorted(found)]
    return CommandResult(ok=True, message=_table_from_pairs("Discovered subdomains", rows))
