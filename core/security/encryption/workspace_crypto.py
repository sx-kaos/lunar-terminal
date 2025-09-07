#!/usr/bin/env python3
# core/security/encryption/workspace_crypto.py
from __future__ import annotations
"""
Workspace-level encryption helpers (tree encrypt / single-file decrypt).

These utilities orchestrate:
  - Discovering plaintext files in a workspace (excluding container & temp types)
  - Streaming encryption using the versioned container
  - Just-in-time in-place decryption for a single file

Public API
----------
encrypt_workspace_tree(workspace_id, workspace_path, db_path, app_root) -> int
decrypt_file_in_place(workspace_id, file_path, db_path, app_root) -> None
"""

from pathlib import Path
from typing import Iterable

from .aead_container import encrypt_stream, decrypt_stream, V2

# Files we never re-encrypt
EXCLUDE_EXTS: set[str] = {".cb1", ".lnk", ".tmp"}


def _iter_plain_files(root: Path) -> Iterable[Path]:
    """Yield plaintext files under root, skipping known exclusions."""
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() not in EXCLUDE_EXTS:
            yield p


def encrypt_workspace_tree(
    workspace_id: str,
    workspace_path: Path,
    db_path: Path,
    app_root: Path,
) -> int:
    """Encrypt all eligible files in the workspace into `.cb1` containers.

    The function replaces each source file by its encrypted counterpart with the
    same name but `.cb1` extension appended (e.g., `report.txt` → `report.txt.cb1`).

    Args:
        workspace_id: Current workspace ID used to fetch the DEK.
        workspace_path: Absolute path to the workspace root.
        db_path: Path to keystore database (global).
        app_root: Base root used by keystore for sidecar files (HMAC, etc).

    Returns:
        Count of files successfully encrypted.
    """
    # Lazy import to avoid cycles
    from core.db.vault.keystore import load_workspace_key

    key = load_workspace_key(db_path, app_root, workspace_id)
    if not key:
        raise RuntimeError("Workspace key not found")

    count = 0
    for src in _iter_plain_files(workspace_path):
        dst = src.with_suffix(src.suffix + ".cb1")
        # Skip if already encrypted previously
        if dst.exists():
            continue
        with src.open("rb") as fi, dst.open("wb") as fo:
            # Default to v2 (ChaCha20-Poly1305, 64-bit counter + per-file HKDF subkey)
            encrypt_stream(fi, fo, key=key, version=V2)
        # Remove the plaintext only after successful write
        src.unlink(missing_ok=True)
        count += 1
    return count


def decrypt_file_in_place(
    workspace_id: str,
    file_path: Path,
    db_path: Path,
    app_root: Path,
) -> None:
    """Decrypt a single file in place (used for on-demand access).

    The function writes `file_path + ".dec"` first and only replaces the original
    upon successful decryption and write/close, to avoid corrupting plaintext on error.

    Args:
        workspace_id: Current workspace ID used to fetch the DEK.
        file_path: Path to a `.cb1` container to decrypt.
        db_path: Path to keystore database (global).
        app_root: Base root used by keystore for sidecar files (HMAC, etc).

    Raises:
        RuntimeError: If the workspace key cannot be loaded.
        ValueError: If the container is invalid or authentication fails.
    """
    # Lazy import to avoid cycles
    from core.db.vault.keystore import load_workspace_key

    key = load_workspace_key(db_path, app_root, workspace_id)
    if not key:
        raise RuntimeError("Workspace key not found")

    tmp = file_path.with_suffix(file_path.suffix + ".dec")
    with file_path.open("rb") as fi, tmp.open("wb") as fo:
        decrypt_stream(fi, fo, key=key)
    tmp.replace(file_path)
