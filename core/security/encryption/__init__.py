#!/usr/bin/env python3
# core/security/encryption/__init__.py
# core/security/encryption/__init__.py
from __future__ import annotations
"""
Encryption package.

Import submodules explicitly to avoid circular imports, e.g.:

from core.security.encryption.dpapi import protect, unprotect
from core.security.encryption.aead_container import encrypt_stream, decrypt_stream
from core.security.encryption.workspace_crypto import encrypt_workspace_tree, decrypt_file_in_place
"""

__all__: list[str] = []
