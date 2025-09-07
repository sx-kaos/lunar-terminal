#!/usr/bin/env python3
# core/security/encryption/dpapi.py
from __future__ import annotations
"""
Minimal Windows DPAPI wrapper.

Encrypts/decrypts small blobs (e.g., workspace DEKs) bound to the current user.
On non-Windows, raises OSError to force explicit fallback handling.

Public API
----------
protect(data: bytes, *, description: str = "") -> bytes
unprotect(data: bytes) -> bytes
"""

import ctypes
import os
from ctypes import wintypes


# Flags (see CryptProtectData/CryptUnprotectData docs)
CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4  # optional machine scope (unused here)


class DATA_BLOB(ctypes.Structure):
    """DATA_BLOB as required by DPAPI."""
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _ensure_windows() -> None:
    """Raise OSError if not on Windows."""
    if os.name != "nt":
        raise OSError("DPAPI is only available on Windows")


def _to_blob(data: bytes) -> DATA_BLOB:
    """Convert Python bytes to a DATA_BLOB."""
    buf = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _from_blob(blob: DATA_BLOB) -> bytes:
    """Copy bytes out of a DATA_BLOB and free with LocalFree."""
    ptr = ctypes.cast(blob.pbData, ctypes.c_void_p)
    size = int(blob.cbData)
    out = ctypes.string_at(ptr, size)
    # LocalFree returns HLOCAL; nonzero indicates failure, but we ignore here.
    ctypes.windll.kernel32.LocalFree(ptr)  # type: ignore[attr-defined]
    return out


def protect(data: bytes, *, description: str = "") -> bytes:
    """Encrypt a blob under the current user context (Windows only).

    Args:
        data: Plain bytes to protect.
        description: Optional description label stored with the blob.

    Returns:
        DPAPI-protected bytes.

    Raises:
        OSError: If DPAPI is unavailable or the OS call fails.
    """
    _ensure_windows()
    in_blob = _to_blob(data)
    out_blob = DATA_BLOB()
    # description is LPWSTR; None is acceptable (no description)
    psz_desc = ctypes.c_wchar_p(description) if description else None
    if not ctypes.windll.crypt32.CryptProtectData(  # type: ignore[attr-defined]
        ctypes.byref(in_blob),
        psz_desc,
        None,  # optional entropy (unused)
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptProtectData failed")
    return _from_blob(out_blob)


def unprotect(data: bytes) -> bytes:
    """Decrypt a DPAPI blob under current context (Windows only).

    Args:
        data: DPAPI-protected bytes.

    Returns:
        The original plaintext bytes.

    Raises:
        OSError: If DPAPI is unavailable or the OS call fails.
    """
    _ensure_windows()
    in_blob = _to_blob(data)
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore[attr-defined]
        ctypes.byref(in_blob),
        None,
        None,  # optional entropy (unused)
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptUnprotectData failed")
    return _from_blob(out_blob)
