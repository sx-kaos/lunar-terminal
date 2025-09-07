# Lunar Terminal Architecture Guide

This guide explains the internal structure of Lunar Terminal, focusing on how the codebase is organized and how the major components interact.

---

## High-Level Overview

Lunar Terminal is organized into modular subpackages under the `core/` directory. Each subpackage is responsible for a distinct concern:

- **boot/** – Startup sequence, environment detection, workspace resolution, database initialization, and command loading.
- **commands/** – Defines the command abstraction (`Command`, `CommandResult`), registry (`CommandRegistry`), and decorators for registering commands.
- **db/** – Handles persistence using SQLite: configuration loading, command catalog, and workspace catalog.
- **helpers/** – Collects system information (CPU, GPU, RAM, Kernel, Disks) using PowerShell CIM (when available) or ctypes/platform APIs.
- **interface/** – Provides the CLI frontends, input handling, command parsing, autocompletion, dispatching, and dynamic plugin loading.
- **security/** – Implements the secure workspace model: sandboxed path resolution, Windows ACL/EFS hardening, and reparse point blocking.
- **ui/** – Terminal UI helpers: ANSI color utilities, rich markup, tables, spinners, progress bars, and logging.

---

## Core Packages and Responsibilities

### 1. Boot
- **File:** `core/boot/boot.py`
- **Purpose:** Orchestrates the full startup pipeline using `_step()` with `[  OK  ]` / `[FAILED]` markers.
- **Key Output:** Returns a `BootState` dataclass with root path, logger, config, loaded command count, and system info.

### 2. Commands
- **Files:** `command_types.py`, `commands.py`
- **Purpose:** Encapsulates commands as first-class objects.
- **Highlights:**
  - `Command`: Metadata + callback + category + completers + aliases.
  - `CommandResult`: Structured result container (`ok`, `message`, `data`).
  - `CommandRegistry`: Central in-memory registry, with support for aliases, categories, and descriptions.
  - `@command` decorator: Simplifies command creation.

### 3. Database
- **Files:** `config.py`, `db.py`
- **Purpose:** Provides global persistence via SQLite (`catalog.db` in workspace root).
- **Responsibilities:**
  - Stores command definitions for persistence across runs.
  - Tracks workspaces (id, slug, nickname, path, timestamps, tags, archived flag).
  - Self-heals catalog by archiving missing workspace folders.

### 4. Helpers
- **File:** `sysinfo.py`
- **Purpose:** Zero-dependency system info collection for Windows (CPU, GPU, RAM, kernel, disks).
- **Outputs:** `SysInfo` dataclass for display and diagnostics.

### 5. Interface
- **Files:** `cli.py`, `completion.py`, `handler.py`, `loader.py`, `parser.py`
- **Purpose:** Provides interactive shell, parsing, and dispatching.
- **Highlights:**
  - CLI: Multiple frontends (PromptToolkit, Readline, Plain).
  - Completion: Token-aware suggestions (built-ins, commands, categories, args).
  - Handler: Dispatches commands with support for chaining (`&&`, `||`), pipes, and redirection (sandboxed).
  - Loader: Dynamically discovers `entrypoint.py` under plugin packages and registers commands.
  - Parser: Tokenizes and binds arguments to function signatures with type- and path-aware coercion.

### 6. Security
- **Files:** `sanitize.py`, `secure_dir.py`
- **Purpose:** Ensures file operations are safe and restricted to secure workspaces.
- **Highlights:**
  - `resolve_in_sandbox`: Ensures all paths remain inside workspace root.
  - Windows-specific hardening: EFS encryption, ACL adjustments, reparse point blocking.
  - Workspace lifecycle: create, switch, adopt existing folders, track current workspace.

### 7. UI
- **Subpackages:** `utils/`, `static/`, `animated/`
- **Purpose:** Provides terminal-friendly output and user experience enhancements.
- **Highlights:**
  - `utils/ansi.py`: ANSI map, colorize, markup rendering, OSC-8 hyperlinks, Windows VT enabling.
  - `utils/console.py`: Thread-safe print functions, terminal title, column detection.
  - `static/logging.py`: Color-aware logging with Windows fallback + rotating file logs.
  - `static/table.py`: ANSI-safe table formatting and printing.
  - `animated/`: ProgressBar and Spinner with shared print mutex.

---

## Data Flow Summary

1. **Startup**: `boot_sequence()` initializes logger, DB, secure workspace, system info, and loads commands.
2. **Command Registration**: Plugins (`entrypoint.py`) and decorated functions register `Command` objects into the registry.
3. **Interactive Loop**: CLI frontend reads input, autocompletion suggests, handler parses and dispatches.
4. **Execution**: `Command.invoke()` is run; arguments are bound and sanitized; results are returned as `CommandResult` or strings.
5. **Persistence**: Registry is synced to DB, workspace catalog is updated, system state is preserved across runs.
6. **Security**: All paths are sandboxed; Windows-specific hardening is applied; TEMP/TMP scoped to workspace.

---

## Next Steps

- [Plugin Development Guide](plugins.md)
- [Security Model](security.md)
