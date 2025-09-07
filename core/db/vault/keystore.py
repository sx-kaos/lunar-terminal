#!/usr/bin/env python3
# core/db/vault/keystore.py
from __future__ import annotations

"""SQLite keystore storing per-workspace DEKs with pluggable wrapping.

Backends:
- dpapi (Windows legacy/optional): DPAPI protect/unprotect (version=1, meta=NULL).
- aes-gcm (cross-platform): KEK from scrypt(passphrase|keyfile) → AES-256-GCM wrap (version=2, meta JSON).
- chachapoly1305 (cross-platform): KEK from scrypt(passphrase|keyfile) → ChaCha20-Poly1305 wrap (version=2, meta JSON).

Schema migration (idempotent on startup):
- meta TEXT (JSON with wrap params and scrypt salt/params)
- version INTEGER (1=DPAPI legacy, 2=portable rows)

Integrity tag:
- `meta_hmac` retained for backward compatibility. For v2, the AEAD tag already
  authenticates the wrapped DEK, but we keep meta_hmac over stable fields to
  detect tampering in the DB row itself.

Notes:
- Callers do NOT change; they still call:
    create_or_rotate_workspace_key(workspace_id, *, db_path=None, app_root=None, rotate=False)
    load_workspace_key(db_path, app_root, workspace_id) -> bytes | None
- The `algo` column describes the DATA container suite for files (e.g., "chacha20poly1305").
  It does not control the wrapping algorithm for the DEK (see meta.wrap_alg).
"""

import json
import hmac
import os
import sqlite3
import time
from hashlib import sha256, scrypt as _scrypt
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from core.security import base_workspace_root

# ==== Optional DPAPI (Windows) =================================================
try:
    from core.security.encryption.dpapi import (
        protect as dpapi_protect,
        unprotect as dpapi_unprotect,
    )
    _DPAPI_AVAILABLE = True
except Exception:  # noqa: BLE001
    _DPAPI_AVAILABLE = False

# ==== Backend selection ========================================================


def _select_wrap_backend() -> str:
    """
    Decide the wrapping backend.

    Order:
      1) KEYSTORE_BACKEND env var ('dpapi'|'aes-gcm'|'chachapoly1305')
      2) DPAPI if available on Windows -> 'dpapi'
      3) default 'aes-gcm' elsewhere
    """
    val = (os.environ.get("KEYSTORE_BACKEND") or "").strip().lower()
    if val in {"dpapi", "aes-gcm", "chachapoly1305"}:
        return val
    return "dpapi" if (_DPAPI_AVAILABLE and os.name == "nt") else "aes-gcm"


# ==== KEK derivation (scrypt or keyfile) ======================================

def _derive_kek(passphrase: Optional[str], *, keyfile: Optional[Path],
                salt: bytes, n: int, r: int, p: int) -> tuple[bytes, str]:
    """Derive a 32B KEK either from a passphrase (scrypt) or from a keyfile.

    Args:
        passphrase: Passphrase string; if None, must provide keyfile.
        keyfile: Path to a 32B key file; if None, must provide passphrase.
        salt, n, r, p: scrypt parameters (ignored for keyfile).

    Returns:
        (kek, derivation_label) where derivation_label is 'scrypt' or 'keyfile'.
    """
    if keyfile:
        raw = Path(keyfile).read_bytes()
        if len(raw) != 32:
            raise ValueError("KEYSTORE_KEYFILE must contain exactly 32 bytes")
        return raw, "keyfile"
    if passphrase is None:
        raise ValueError(
            "Missing KEYSTORE_PASSPHRASE or KEYSTORE_KEYFILE for portable backend")
    kek = _scrypt(passphrase.encode("utf-8"),
                  salt=salt, n=n, r=r, p=p, dklen=32)
    return kek, "scrypt"


def _wrap_dek_aes(dek: bytes, kek: bytes) -> tuple[bytes, dict]:
    """Wrap a 32B DEK with AES-256-GCM using a 12B random nonce."""
    if len(dek) != 32:
        raise ValueError("DEK must be 32 bytes")
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, dek, None)
    return ct, {"wrap_alg": "aes-256-gcm", "nonce": nonce.hex()}


def _unwrap_dek_aes(ct: bytes, meta: dict, kek: bytes) -> bytes:
    """Unwrap a DEK previously wrapped by AES-256-GCM."""
    nonce = bytes.fromhex(str(meta["nonce"]))
    return AESGCM(kek).decrypt(nonce, ct, None)


def _wrap_dek_chacha(dek: bytes, kek: bytes) -> tuple[bytes, dict]:
    """Wrap a 32B DEK with ChaCha20-Poly1305 using a 12B random nonce."""
    if len(dek) != 32:
        raise ValueError("DEK must be 32 bytes")
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(kek).encrypt(nonce, dek, None)
    return ct, {"wrap_alg": "chacha20poly1305", "nonce": nonce.hex()}


def _unwrap_dek_chacha(ct: bytes, meta: dict, kek: bytes) -> bytes:
    """Unwrap a DEK previously wrapped by ChaCha20-Poly1305."""
    nonce = bytes.fromhex(str(meta["nonce"]))
    return ChaCha20Poly1305(kek).decrypt(nonce, ct, None)


# ==== SQLite plumbing ===========================================================

def get_vault_db_path() -> Path:
    """Global keystore DB path under the base workspace root."""
    base = base_workspace_root()
    base.mkdir(parents=True, exist_ok=True)
    return (base / "keystore.sqlite").resolve()


def _open(db_path: Path | None = None) -> sqlite3.Connection:
    p = db_path or get_vault_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=FULL;")
    con.execute("PRAGMA secure_delete=ON;")
    con.execute("PRAGMA trusted_schema=OFF;")
    con.row_factory = sqlite3.Row
    return con


def _hmackey_path(root: Path, *, dpapi_mode: bool) -> Path:
    return root / ("keystore_hmackey.dpapi" if dpapi_mode else "keystore_hmackey.bin")


def _load_hmac_key(root: Path, *, backend: str) -> bytes:
    """
    HMAC key store:
      - 'dpapi' backend: DPAPI-protected file on Windows (legacy behavior).
      - other backends: raw 32B file next to the DB.
    """
    dpapi_mode = backend == "dpapi" and _DPAPI_AVAILABLE and os.name == "nt"
    p = _hmackey_path(root, dpapi_mode=dpapi_mode)

    if p.exists():
        if dpapi_mode:
            return dpapi_unprotect(p.read_bytes())
        return p.read_bytes()

    raw = os.urandom(32)
    if dpapi_mode:
        p.write_bytes(dpapi_protect(raw, description="cst-keystore-hmac"))
    else:
        p.write_bytes(raw)
    return raw


def _column_names(con: sqlite3.Connection) -> set[str]:
    cols = set()
    for row in con.execute("PRAGMA table_info(keystore)"):
        cols.add(str(row["name"]))
    return cols


def init_keystore(db_path: Path | None = None) -> None:
    """
    Ensure keystore exists and migrate schema (meta, version).
    """
    con = _open(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS keystore (
                workspace_id TEXT PRIMARY KEY,
                algo TEXT NOT NULL,
                wrapped_key BLOB NOT NULL,
                meta_hmac BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        cols = _column_names(con)
        if "meta" not in cols:
            try:
                con.execute("ALTER TABLE keystore ADD COLUMN meta TEXT")
            except Exception:
                pass
        if "version" not in cols:
            try:
                con.execute(
                    "ALTER TABLE keystore ADD COLUMN version INTEGER DEFAULT 1")
            except Exception:
                pass
        con.commit()
    finally:
        con.close()


def keystore_exists(db_path: Path | None = None) -> bool:
    p = db_path or get_vault_db_path()
    return p.exists()


# ==== Public API ================================================================

def create_or_rotate_workspace_key(
    workspace_id: str,
    *,
    db_path: Path | None = None,
    app_root: Path | None = None,
    rotate: bool = False,
) -> None:
    """Create or rotate a workspace DEK and store wrapped value.

    Args:
        workspace_id: Workspace identifier.
        db_path: Optional override path to keystore DB.
        app_root: Base root for auxiliary files (HMAC key).
        rotate: If True, always replace with a fresh DEK; else create if missing.

    Behavior:
        - Backend selection via KEYSTORE_BACKEND: 'dpapi'|'aes-gcm'|'chachapoly1305'.
        - v1 rows: DPAPI-wrapped (legacy) with meta=NULL, version=1.
        - v2 rows: portable wrap with meta JSON and version=2.
        - meta_hmac is always written for compatibility.
    """
    init_keystore(db_path)
    backend = _select_wrap_backend()
    root = app_root or base_workspace_root()
    hmackey = _load_hmac_key(root, backend=backend)

    con = _open(db_path)
    try:
        # Avoid overwriting unless rotate=True
        row = con.execute(
            "SELECT workspace_id FROM keystore WHERE workspace_id=?", (
                workspace_id,)
        ).fetchone()
        if row and not rotate:
            return

        dek = os.urandom(32)

        if backend == "dpapi":
            if not _DPAPI_AVAILABLE:
                raise OSError(
                    "DPAPI backend selected but unavailable on this platform")
            wrapped = dpapi_protect(dek, description=f"cst-ws:{workspace_id}")
            algo = "chacha20poly1305"  # data container suite (files)
            meta_json = None
            version = 1
        else:
            # Portable backends need KEK: passphrase (scrypt) or keyfile
            keyfile_env = os.environ.get("KEYSTORE_KEYFILE")
            pass_env = os.environ.get("KEYSTORE_PASSPHRASE")
            n = int(os.environ.get("SCRYPT_N", "16384"))
            r = int(os.environ.get("SCRYPT_R", "8"))
            p = int(os.environ.get("SCRYPT_P", "1"))
            salt = os.urandom(16)
            kek, klabel = _derive_kek(
                pass_env if not keyfile_env else None,
                keyfile=Path(keyfile_env) if keyfile_env else None,
                salt=salt, n=n, r=r, p=p,
            )
            if backend == "aes-gcm":
                wrapped, wmeta = _wrap_dek_aes(dek, kek)
                wrap_alg = "aes-256-gcm"
            elif backend == "chachapoly1305":
                wrapped, wmeta = _wrap_dek_chacha(dek, kek)
                wrap_alg = "chacha20poly1305"
            else:
                raise ValueError(f"Unsupported backend: {backend}")

            algo = "chacha20poly1305"  # data container suite (files)
            meta = {
                "wrap_alg": wrap_alg,
                "kek": klabel,        # 'scrypt' or 'keyfile'
                "salt": salt.hex(),   # scrypt salt (ignored if keyfile)
                "n": n, "r": r, "p": p,
                "nonce": wmeta["nonce"],
            }
            meta_json = json.dumps(meta, separators=(",", ":"), sort_keys=True)
            version = 2

        payload_for_hmac = f"{workspace_id}|{algo}|{meta_json or ''}".encode(
            "utf-8")
        tag = hmac.new(hmackey, payload_for_hmac, sha256).digest()
        now = int(time.time())

        # Upsert
        con.execute(
            """
            INSERT INTO keystore(workspace_id, algo, wrapped_key, meta_hmac, created_at, meta, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET
                wrapped_key=excluded.wrapped_key,
                meta_hmac=excluded.meta_hmac,
                created_at=excluded.created_at,
                meta=excluded.meta,
                version=excluded.version
            """,
            (workspace_id, algo, wrapped, tag, now, meta_json, version),
        )
        con.commit()
    finally:
        con.close()


def load_workspace_key(
    db_path: Path | None,
    app_root: Path | None,
    workspace_id: str,
) -> Optional[bytes]:
    """Return raw 32-byte DEK for a workspace, or None if absent.

    Args:
        db_path: Optional override to keystore DB.
        app_root: Base path for local HMAC key file.
        workspace_id: Identifier to fetch.

    Returns:
        32-byte DEK or None.

    Raises:
        ValueError: Integrity failure on meta_hmac mismatch.
        OSError: Missing passphrase/keyfile for portable backends, or DPAPI unavailable.
    """
    init_keystore(db_path)
    con = _open(db_path)
    try:
        row = con.execute(
            "SELECT algo, wrapped_key, meta_hmac, COALESCE(meta,'' ) AS meta, COALESCE(version,1) AS version "
            "FROM keystore WHERE workspace_id=?",
            (workspace_id,),
        ).fetchone()
    finally:
        con.close()

    if not row:
        return None

    algo: str = row["algo"]                     # data container suite (files)
    wrapped: bytes = row["wrapped_key"]
    tag: bytes = row["meta_hmac"]
    meta: str = row["meta"]
    version: int = int(row["version"])

    backend = _select_wrap_backend()
    root = app_root or base_workspace_root()
    hmackey = _load_hmac_key(root, backend=backend)
    payload_for_hmac = f"{workspace_id}|{algo}|{meta}".encode("utf-8")
    expect = hmac.new(hmackey, payload_for_hmac, sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("Keystore integrity check failed")

    if version == 1:
        # Legacy DPAPI row
        if not _DPAPI_AVAILABLE:
            raise OSError(
                "DPAPI row present but DPAPI unavailable on this platform")
        return dpapi_unprotect(wrapped)

    # v2 portable row
    meta_obj = json.loads(meta) if meta else {}
    wrap_alg = str(meta_obj.get("wrap_alg", ""))
    klabel = str(meta_obj.get("kek", "scrypt"))
    salt = bytes.fromhex(meta_obj.get("salt", "")
                         ) if klabel == "scrypt" else b""
    n = int(meta_obj.get("n", 16384))
    r = int(meta_obj.get("r", 8))
    p = int(meta_obj.get("p", 1))
    nonce_hex = str(meta_obj.get("nonce", ""))

    keyfile_env = os.environ.get("KEYSTORE_KEYFILE")
    pass_env = os.environ.get("KEYSTORE_PASSPHRASE")

    kek, _ = _derive_kek(
        pass_env if (klabel == "scrypt" and not keyfile_env) else None,
        keyfile=Path(keyfile_env) if keyfile_env else (
            None if klabel == "scrypt" else None),
        salt=salt or os.urandom(16),  # unused when keyfile is used
        n=n, r=r, p=p,
    )

    meta_for_alg = {"nonce": nonce_hex}
    if wrap_alg == "aes-256-gcm":
        return _unwrap_dek_aes(wrapped, meta_for_alg, kek)
    if wrap_alg == "chacha20poly1305":
        return _unwrap_dek_chacha(wrapped, meta_for_alg, kek)

    raise ValueError(f"Unsupported wrap_alg in keystore row: {wrap_alg}")
