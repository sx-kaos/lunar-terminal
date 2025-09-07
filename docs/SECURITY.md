# Lunar Terminal Security Model

Lunar Terminal enforces a **multi-layer security model** combining sandboxed
workspaces, Windows hardening, strict path validation, and authenticated
encryption-at-rest. This document summarizes the guarantees, mechanisms, and
residual risks.

---

## Secure Workspaces

Each session runs inside a **secure workspace** located under the base root:

- **Windows:** `%LOCALAPPDATA%/Lunar Terminal/workspace/<slug>`  
- **POSIX:** `~/.Lunar/workspace/<slug>`  

### Features
- Workspaces are opaque 32-hex identifiers (UUID style).  
- A pointer file `.last_workspace` remembers the last active workspace.  
- Each workspace is tracked in the global SQLite catalog (`catalog.db`).  
- TEMP/TMP are confined to `<workspace>/.tmp/`.  

---

## Path Sandboxing

The core security layer is **strict path resolution**:

- `resolve_in_sandbox(path)` ensures all paths remain inside the active workspace.  
- On **Windows**, traversal through *any* junction/symlink (reparse point) inside the workspace is denied.  
- Additional sanitization:  
  - **NTFS ADS** (`file:stream`) blocked.  
  - **Reserved device names** (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) blocked.  
- Developers may use `@sandbox_paths` to auto-sanitize function parameters.  

---

## Encryption at Rest

All sensitive workspace content is encrypted using an **AEAD container format**.

### Container Format (`.cb1`)
- Magic: `LV1\0` + version `1`.  
- Algorithm: **ChaCha20-Poly1305** (IETF 12-byte nonce).  
- Nonce = 8-byte random prefix + 4-byte counter.  
- Chunked I/O (default 64 KiB per chunk).  
- Authenticated header (AAD) with versioning.  
- Limits: ≤ 4 GiB per file (due to 32-bit chunk counter).  

### Scope
- `encrypt_workspace_tree()` walks the workspace and converts eligible files into `.cb1`.  
- Exclusions: `.cb1`, `.lnk`, `.tmp`.  
- `decrypt_file_in_place()` provides just-in-time access, replacing ciphertext with plaintext.  

### Key Management
- Each workspace has a 32-byte **data encryption key (DEK)**.  
- DEK is wrapped at rest via **Windows DPAPI** (user scope).  
- Stored in the global keystore (`core.db.vault.keystore`).  
- Non-Windows: DPAPI unavailable → encryption disabled (explicit OSError).  

---

## Windows Hardening

Best-effort, non-fatal mechanisms:

- **Hidden + Not Content Indexed** attributes set on workspace folders and pointer files.  
- **ACL tightening** via `icacls`: SYSTEM + current user full control, inheritance removed, broad groups removed.  
- **EFS encryption** (`EncryptFileW`) if not disabled (`CST_DISABLE_EFS`).  
- **TEMP isolation** enforced for process + children.  

---

## Threat Model

### Protects Against
- Accidental or malicious escape from workspaces.  
- File exfiltration outside the active sandbox.  
- Offline theft of workspace content (encrypted at rest).  
- Indexing/search exposure (Windows).  

### Does Not Protect Against
- Compromise of the user’s session (DPAPI available to same user).  
- Malware running with user privileges.  
- Plaintext exposure during active use (in RAM / decrypted files).  
- Cross-platform portability (DPAPI keys are per-user, Windows-only).  

---

## Operational Notes

- Catalog auto-heals: missing workspaces are archived.  
- Pointer file `.last_workspace` is best-effort only (DB remains source of truth).  
- Bulk encryption is one-way; decrypt only on demand.  
- Developers should always sanitize file paths before passing to system APIs.  

---

## Summary

Lunar Terminal workspaces combine:

- Sandboxing (strict path validation).  
- Encryption-at-rest (ChaCha20-Poly1305 containers, DPAPI-wrapped keys).  
- Windows hardening (ACLs, EFS, hidden/indexing flags).  
- Catalog + pointer file for lifecycle continuity.  

This layered model defends primarily against **offline attacks** and **workspace
escape**, while maintaining developer ergonomics with auto-sanitization
decorators and transparent lifecycle management.
