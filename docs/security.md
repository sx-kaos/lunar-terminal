# Lunar Terminal Security Model

Lunar Terminal was designed with a **secure workspace model** to ensure that commands and plugins cannot accidentally (or maliciously) escape their designated environment.  
This document explains the security mechanisms and developer guidelines for working safely within Lunar Terminal.

---

## Secure Workspaces

Every session operates inside a **secure workspace** located under the workspace root:

- **Windows:** `%LOCALAPPDATA%/Lunar/workspace/<slug>`  
- **POSIX:** `~/.Lunar/workspace/<slug>`  

Each workspace has a unique **slug** (UUID-style hex) and is tracked in the global SQLite catalog (`catalog.db`).

### Features
- Workspace folders are hidden on Windows (via file attributes).
- A `.hardened` marker file is used to record that the workspace has undergone initial hardening.
- TEMP/TMP environment variables are scoped inside the workspace (`.tmp/`).

---

## Path Sandboxing

The core of the security model is **path sandboxing**:

- `resolve_in_sandbox(path)` ensures all resolved paths stay inside the current secure workspace.
- Any attempt to reference paths outside the workspace raises a `PermissionError`.
- Windows-specific defenses:
  - Blocks traversal through **reparse points** (junctions/symlinks).
  - Denies use of **Alternate Data Streams (ADS)** like `file.txt:stream`.
  - Prevents usage of reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`, etc.).

### Developer Guidelines
- Always sanitize user-supplied paths with `sanitize_path()`.
- When defining commands, prefer type hints (`Path`) or parameter names (`path`, `file`, `dir`) that trigger auto-sanitization in the parser.
- Use the `@sandbox_paths("param")` decorator if your command accepts paths.

---

## Windows Hardening

On Windows, additional best-effort hardening is applied:

- **ACLs (icacls):**
  - Removes inherited permissions.
  - Grants only `SYSTEM` and the current user full control.
  - Removes broad groups (`Users`, `Authenticated Users`, `Everyone`).

- **EFS Encryption:**
  - Calls `EncryptFileW` to encrypt workspaces per-user, when not disabled (`CST_DISABLE_EFS`).

- **TEMP Isolation:**
  - Redirects `%TMP%` and `%TEMP%` to a `.tmp/` folder within the workspace.

These steps reduce exposure but are considered **best-effort** (non-fatal if skipped).

---

## Workspace Lifecycle

- **create_secure_workspace()** – Creates a new secure workspace, applies hardening, and inserts it into the catalog.
- **switch_secure_workspace(identifier)** – Switches to an existing workspace (id, slug, nickname, or short-id prefix).
- **setup_secure_workspace()** – Initializes session: reopens last workspace or creates a new one.
- **adopt_current_cwd_as_workspace()** – Allows adopting an existing folder under the workspace root.

Each operation updates the global state variables:
- `SECURE_WORKSPACE_ROOT`: Current workspace path.
- `CURRENT_WORKSPACE_ID`: Current workspace identifier.

---

## Security and Command Execution

When commands are executed:
- Input arguments are bound using `parser.bind_args()`.
- Path-like annotations or names trigger `sanitize_path()` automatically.
- File redirection (`>`, `>>`) uses `resolve_in_sandbox()` to ensure safe writes.
- Pipes (`|`) inject output into safe parameters like `stdin`, `data`, or `content`.

---

## Developer Best Practices

- **Never** bypass sandbox helpers (`sanitize_path`, `resolve_in_sandbox`).
- Treat **relative paths** as relative to the current secure workspace.
- Avoid using `subprocess(..., shell=True)` when writing plugins; prefer explicit argument lists.
- If working on Windows, assume ACL/EFS hardening may fail gracefully — design commands to remain functional.

---

## Next Steps

- [Architecture Guide](architecture.md)  
- [Plugin Development Guide](plugins.md)
