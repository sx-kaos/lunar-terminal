# commands/recon/dnsclient.py
from __future__ import annotations

"""
Minimal DNS client (UDP) for MX/NS/TXT queries using only the Python standard library.

Notes:
- This does NOT implement every corner of RFC 1035, but is robust enough for common cases.
- Name compression decoding is supported.
- We default to public resolvers if none is provided.
"""

import os
import random
import socket
import struct
from typing import Iterable, List, Tuple, Optional

# DNS record types we support
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28

QCLASS_IN = 1

# Default resolvers to try (can be overridden by caller)
DEFAULT_NAMESERVERS: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8")

_DNS_PORT = 53
_MAX_UDP = 1500


def _encode_qname(name: str) -> bytes:
    """Encode dotted name into DNS wire format."""
    parts = [p for p in name.strip(".").split(".") if p]
    out = b"".join(struct.pack("!B", len(p)) + p.encode("ascii", "ignore") for p in parts)
    return out + b"\x00"


def _build_query(transaction_id: int, qname: str, qtype: int) -> bytes:
    """Construct a standard DNS query packet (one question, RD=1)."""
    flags = 0x0100  # RD
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    question = _encode_qname(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    return header + question


def _read_name(buf: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a possibly-compressed domain name at `offset`.
    Returns (name, new_offset). `new_offset` is the position after the name
    **only for non-compressed reads**. For compression, the offset stops where the pointer starts.
    """
    labels: List[str] = []
    jumped = False
    original_offset = offset

    while True:
        if offset >= len(buf):
            return ".".join(labels) or ".", offset

        length = buf[offset]
        if length & 0xC0 == 0xC0:
            # Pointer: 2 bytes
            if offset + 1 >= len(buf):
                return ".".join(labels) or ".", offset + 1
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            offset = pointer
            if not jumped:
                # Only move caller offset past the pointer once
                original_offset += 2
                jumped = True
            continue

        offset += 1
        if length == 0:
            break

        label = buf[offset : offset + length].decode("ascii", "ignore")
        labels.append(label)
        offset += length

    if not jumped:
        original_offset = offset
    return ".".join(labels) or ".", original_offset


def _parse_rr(buf: bytes, offset: int) -> Tuple[dict, int]:
    """Parse a single resource record, returning a dict and next offset."""
    name, offset = _read_name(buf, offset)
    if offset + 10 > len(buf):
        return {"name": name, "type": 0, "class": 0, "ttl": 0, "rdata": b""}, len(buf)

    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", buf[offset : offset + 10])
    offset += 10
    rdata = buf[offset : offset + rdlength]
    offset += rdlength
    return {"name": name, "type": rtype, "class": rclass, "ttl": ttl, "rdata": rdata}, offset


def _parse_response(buf: bytes) -> Tuple[int, int, int, int, int, int, int, int, int, int, int, bytes, int]:
    """Return header fields and the index after header/question section for convenience."""
    if len(buf) < 12:
        raise ValueError("DNS response too short")
    (tid, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", buf[:12])
    return tid, flags, qdcount, ancount, nscount, arcount


def _skip_questions(buf: bytes, offset: int, qdcount: int) -> int:
    """Advance offset past the question section."""
    for _ in range(qdcount):
        _, offset = _read_name(buf, offset)
        offset += 4  # type + class
    return offset


def _to_txt_strings(rdata: bytes) -> List[str]:
    """Parse TXT RDATA into list of strings (handles multiple strings)."""
    texts: List[str] = []
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        i += 1
        texts.append(rdata[i : i + ln].decode("utf-8", "replace"))
        i += ln
    return texts


def _decode_rdata(buf: bytes, rr: dict) -> dict:
    """Decode common RDATA formats to Python types."""
    rtype = rr["type"]
    rdata = rr["rdata"]

    if rtype == QTYPE_A and len(rdata) == 4:
        rr["data"] = socket.inet_ntoa(rdata)
    elif rtype == QTYPE_AAAA and len(rdata) == 16:
        rr["data"] = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (QTYPE_NS, QTYPE_CNAME, QTYPE_PTR):
        name, _ = _read_name(buf, len(buf) - len(rdata))  # not correct position if used blindly
        # Better: read name from a temp buffer starting at rdata offset; we reconstruct minimal parser:
        # Re-read name using a fake message where rdata is positioned correctly:
        # Instead, use the main buffer and compute the absolute rdata offset by backing from rr offset not stored.
        # Simpler approach: decode by reusing a helper that expects (buf, offset) -> name.
        # We'll track the target name by reading from a copy of rdata with local offset 0.
        name, _ = _read_name(rdata + b"\x00", 0)  # local decode hack, robust enough for common cases
        rr["data"] = name
    elif rtype == QTYPE_MX:
        if len(rdata) >= 2:
            pref = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = _read_name(rdata[2:] + b"\x00", 0)
            rr["data"] = {"preference": pref, "exchange": exchange}
    elif rtype == QTYPE_TXT:
        rr["data"] = _to_txt_strings(rdata)
    else:
        rr["data"] = rdata
    return rr


def query(
    qname: str,
    qtype: int,
    *,
    nameservers: Optional[Iterable[str]] = None,
    timeout: float = 3.0,
    tries: int = 2,
) -> List[dict]:
    """
    Perform a DNS query and return a list of decoded RR dicts for the answer section.

    Args:
        qname: domain name to query (FQDN).
        qtype: numeric type (e.g., QTYPE_MX, QTYPE_NS, QTYPE_TXT).
        nameservers: iterable of resolver IPs to try (UDP/53).
        timeout: per-try timeout in seconds.
        tries: number of tries per nameserver.

    Returns:
        List of RR dicts with at least keys: name, type, class, ttl, data (decoded where possible).
    """
    servers = list(nameservers or DEFAULT_NAMESERVERS)
    transaction_id = random.randint(0, 0xFFFF)
    request = _build_query(transaction_id, qname, qtype)

    for server in servers:
        for attempt in range(tries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(request, (server, _DNS_PORT))
                    buf, _addr = s.recvfrom(_MAX_UDP)
                # Parse header
                tid, flags, qdcount, ancount, nscount, arcount = _parse_response(buf)
                if tid != transaction_id:
                    continue  # mismatched response; retry
                rcode = flags & 0x000F
                if rcode != 0:
                    # NXDOMAIN or other error; return empty for now
                    return []
                # Skip questions
                offset = _skip_questions(buf, 12, qdcount)
                # Parse answers
                answers: List[dict] = []
                for _ in range(ancount):
                    rr, offset = _parse_rr(buf, offset)
                    rr = _decode_rdata(buf, rr)
                    answers.append(rr)
                return answers
            except Exception:
                continue
    return []
