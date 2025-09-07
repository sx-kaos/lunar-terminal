#!/usr/bin/env python3
# core/security/encryption/aead_container.py
from __future__ import annotations
"""
Versioned, streaming AEAD container (v1 + v2) for workspace files.

This module provides authenticated encryption-at-rest using an on-disk container
format with a small, versioned header (AAD) and chunked ciphertext. It supports:

- v1: ChaCha20-Poly1305 (IETF 96-bit nonce)
      nonce = 8-byte random prefix || 4-byte BE chunk counter (32-bit)
- v2: ChaCha20-Poly1305 (IETF 96-bit nonce) **with 64-bit counter**
      nonce = 4-byte random prefix || 8-byte BE chunk counter (64-bit)
      + per-file subkey via HKDF-SHA256 to mitigate cross-file nonce-prefix reuse.

Both versions use a compact JSON header that is authenticated as AAD.

Public API
----------
encrypt_stream(in_f, out_f, *, key, version=2, chunk_size=65536) -> None
decrypt_stream(in_f, out_f, *, key) -> None

Notes
-----
- Header is encoded as: [u16 header_len][header_json_bytes][ciphertext...]
- Header JSON keys are stable and sorted for deterministic AAD.
- Chunk sizes are written implicitly via per-chunk ciphertext lengths (u32).
- v2 header adds:
    "counter_bytes": 8
    "kdf": "hkdf-sha256"
    "kdf_salt": base64(salt16)

Security rationale (v2)
-----------------------
Because ChaCha20-Poly1305 requires a 12-byte nonce, we adopt a 4B random prefix
plus an 8B counter for a 64-bit space. To avoid any cross-file nonce collision
risk when the same DEK is reused, we derive a *per-file* subkey from the DEK via
HKDF-SHA256 using a random 16-byte salt stored in the header (AAD).
"""

import base64
import io
import json
import os
import struct
from typing import BinaryIO, Final

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --------------------------- constants / header ---------------------------

MAGIC: Final[bytes] = b"LV1\0"  # 4 bytes, constant across versions
V1: Final[int] = 1              # ChaCha20-Poly1305, 8B prefix + 4B counter
# ChaCha20-Poly1305, 4B prefix + 8B counter + HKDF subkey
V2: Final[int] = 2

# Default chunk size (64 KiB) chosen to balance memory and per-chunk overhead
DEFAULT_CHUNK_SIZE: Final[int] = 64 * 1024

# u16 max for header length guard (65,535)
_U16_MAX: Final[int] = 0xFFFF


def _b64e(b: bytes) -> str:
    """urlsafe base64 (no padding)."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    """Decode urlsafe base64 that may omit padding."""
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _write_header(out_f: BinaryIO, header: dict) -> bytes:
    """Serialize and write header, return bytes used as AAD.

    The header is JSON with sorted keys, then length-prefixed by u16.

    Raises:
        ValueError: If the header is larger than 65535 bytes.
    """
    hbytes = json.dumps(
        header, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if len(hbytes) > _U16_MAX:
        raise ValueError("Header too large")
    out_f.write(struct.pack(">H", len(hbytes)))
    out_f.write(hbytes)
    return hbytes  # used as AAD


def _read_header(in_f: BinaryIO) -> tuple[dict, bytes]:
    """Read and parse header, returning (header_dict, aad_bytes)."""
    lb = in_f.read(2)
    if len(lb) != 2:
        raise ValueError("Missing container header")
    (hlen,) = struct.unpack(">H", lb)
    hbytes = in_f.read(hlen)
    if len(hbytes) != hlen:
        raise ValueError("Truncated container header")
    header = json.loads(hbytes.decode("utf-8"))
    return header, hbytes


def _nonce_v1(prefix8: bytes, idx: int) -> bytes:
    """Build v1 12-byte nonce (8B prefix + 4B counter)."""
    if idx < 0 or idx > 0xFFFFFFFF:
        raise ValueError("Chunk index exceeds 32-bit counter space")
    return prefix8 + idx.to_bytes(4, "big")


def _nonce_v2(prefix4: bytes, idx: int) -> bytes:
    """Build v2 12-byte nonce (4B prefix + 8B counter)."""
    if idx < 0 or idx > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Chunk index exceeds 64-bit counter space")
    return prefix4 + idx.to_bytes(8, "big")


def _derive_file_subkey_v2(master_key: bytes, salt16: bytes) -> bytes:
    """Derive a per-file 32-byte subkey via HKDF-SHA256.

    Args:
        master_key: 32B workspace DEK.
        salt16: 16B random salt stored in header.

    Returns:
        32-byte subkey unique to this file.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt16,
        info=b"cst.cb1.v2.filekey",
    )
    return hkdf.derive(master_key)


# ------------------------------ encrypt ------------------------------

def encrypt_stream(
    in_f: BinaryIO,
    out_f: BinaryIO,
    *,
    key: bytes,
    version: int = V2,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Encrypt a stream into the container format.

    Args:
        in_f: Input file-like object (readable, binary).
        out_f: Output file-like object (writable, binary).
        key: 32-byte DEK from the keystore.
        version: Container version (2=ChaCha20-Poly1305, 64-bit counter; 1=ChaCha20-Poly1305, 32-bit).
        chunk_size: Plaintext chunk size in bytes.

    Raises:
        ValueError: On invalid key length, version, or oversized header.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("key must be 32 bytes")

    if version == V1:
        suite = "chacha20poly1305"
        # v1 uses the master key directly
        aead = ChaCha20Poly1305(key)
        nonce_prefix = os.urandom(8)    # 8B prefix
        counter_bytes = 4               # 32-bit counter
        header = {
            "magic": _b64e(MAGIC),
            "v": V1,
            "suite": suite,
            "nonce_prefix": _b64e(nonce_prefix),
            "counter_bytes": counter_bytes,
            "chunk_size": int(chunk_size),
        }
        aad = _write_header(out_f, header)
        idx = 0
        while True:
            pt = in_f.read(chunk_size)
            if not pt:
                break
            nonce = _nonce_v1(nonce_prefix, idx)
            ct = aead.encrypt(nonce, pt, aad)
            out_f.write(struct.pack(">I", len(ct)))
            out_f.write(ct)
            idx += 1
        return

    if version != V2:
        raise ValueError(f"Unsupported container version: {version}")

    # v2: derive a per-file subkey via HKDF-SHA256
    suite = "chacha20poly1305"
    file_salt = os.urandom(16)
    subkey = _derive_file_subkey_v2(bytes(key), file_salt)
    aead = ChaCha20Poly1305(subkey)
    nonce_prefix = os.urandom(4)    # 4B prefix (random per file)
    counter_bytes = 8               # 64-bit counter

    header = {
        "magic": _b64e(MAGIC),
        "v": V2,
        "suite": suite,
        "nonce_prefix": _b64e(nonce_prefix),
        "counter_bytes": counter_bytes,
        "chunk_size": int(chunk_size),
        "kdf": "hkdf-sha256",
        "kdf_salt": _b64e(file_salt),
    }
    aad = _write_header(out_f, header)

    idx = 0
    while True:
        pt = in_f.read(chunk_size)
        if not pt:
            break
        nonce = _nonce_v2(nonce_prefix, idx)
        ct = aead.encrypt(nonce, pt, aad)
        out_f.write(struct.pack(">I", len(ct)))
        out_f.write(ct)
        idx += 1


# ------------------------------ decrypt ------------------------------

def decrypt_stream(in_f: BinaryIO, out_f: BinaryIO, *, key: bytes) -> None:
    """Decrypt a stream from the container format.

    Args:
        in_f: Input file-like object (readable, binary).
        out_f: Output file-like object (writable, binary).
        key: 32-byte DEK from the keystore.

    Raises:
        ValueError: On invalid key length, bad header, or authentication failure.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("key must be 32 bytes")

    header, aad = _read_header(in_f)
    try:
        magic = _b64d(header["magic"])
        if magic != MAGIC:
            raise ValueError("Bad magic")
        version = int(header["v"])
        suite = str(header["suite"])
        counter_bytes = int(header.get(
            "counter_bytes", 4 if version == V1 else 8))
        nonce_prefix_b64 = str(header["nonce_prefix"])
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid header: {exc}") from exc

    nonce_prefix = _b64d(nonce_prefix_b64)

    if version == V1:
        if not (suite == "chacha20poly1305" and counter_bytes == 4 and len(nonce_prefix) == 8):
            raise ValueError(
                "Unsupported or inconsistent v1 header parameters")
        aead = ChaCha20Poly1305(bytes(key))
        nonce_fn = _nonce_v1

    elif version == V2:
        if not (suite == "chacha20poly1305" and counter_bytes == 8 and len(nonce_prefix) == 4):
            raise ValueError(
                "Unsupported or inconsistent v2 header parameters")
        # v2 requires kdf info to derive the per-file subkey
        kdf_name = str(header.get("kdf", ""))
        if kdf_name != "hkdf-sha256":
            raise ValueError("Unsupported kdf in v2 header")
        file_salt_b64 = str(header.get("kdf_salt", ""))
        file_salt = _b64d(file_salt_b64)
        subkey = _derive_file_subkey_v2(bytes(key), file_salt)
        aead = ChaCha20Poly1305(subkey)
        nonce_fn = _nonce_v2

    else:
        raise ValueError(f"Unsupported container version: {version}")

    idx = 0
    while True:
        lb = in_f.read(4)
        if not lb:
            break
        if len(lb) != 4:
            raise ValueError("Truncated chunk length")
        (clen,) = struct.unpack(">I", lb)
        if clen < 16:
            raise ValueError("Invalid chunk length")
        ct = in_f.read(clen)
        if len(ct) != clen:
            raise ValueError("Truncated ciphertext chunk")
        nonce = nonce_fn(nonce_prefix, idx)
        pt = aead.decrypt(nonce, ct, aad)
        out_f.write(pt)
        idx += 1


# ------------------------------ CLI helper (optional) ------------------------------

def _self_test_roundtrip() -> None:  # pragma: no cover - developer sanity check
    """Quick in-memory roundtrip for both versions."""
    data = os.urandom(1_000_000)  # 1 MB
    key = os.urandom(32)
    for ver in (V1, V2):
        buf = io.BytesIO()
        encrypt_stream(io.BytesIO(data), buf, key=key, version=ver)
        buf.seek(0)
        out = io.BytesIO()
        decrypt_stream(buf, out, key=key)
        assert out.getvalue() == data, f"mismatch on v{ver}"


if __name__ == "__main__":  # pragma: no cover
    _self_test_roundtrip()
