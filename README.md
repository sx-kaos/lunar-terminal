# Lunar Terminal

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)

> **A modular, secure, and extensible cybersecurity command-line environment written in Python 3.10+.**
> Hardened workspace model, pluggable commands, intelligent autocompletion, and rich Windows-friendly UI.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Plugins](#plugins)
- [Security](#security)
- [Developer Guide](#developer-guide)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Secure Workspaces
- Auto-hardened per-session directories.
- Windows ACL tightening, EFS encryption, and reparse-point blocking.
- SQLite catalog for persistent workspace and command metadata.
- Sandbox path resolution ensures safe filesystem operations.

### Pluggable Command System
- Commands as first-class objects (`Command`, `CommandResult`).
- Dynamic runtime loading via `entrypoint.py`.
- Aliases, categories, and decorators for flexible registration.
- Argument binding with type-safe coercion.

### Interactive CLI
- Multiple frontends: PromptToolkit (rich), Readline, plain fallback.
- Token-aware completion for commands, categories, and arguments.
- Support for chaining (`&&`, `||`), piping (`|`), and redirection (`>`, `>>`).

### Windows-Friendly UI
- ANSI colorized logging with fallback support.
- Terminal spinners and progress bars.
- Prompt customization with username and hostname.

### System Diagnostics
- Cross-platform CPU, GPU, RAM, kernel, and disk info.
- Zero-dependency collection using PowerShell CIM or ctypes/platform APIs.

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/sx-kaos/lunar-terminal.git
cd lunar-terminal
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

Start the interactive terminal:

```bash
python -m core.main
```

- Type `help` for all commands and categories.
- Use `help <category>` or `help <command>` for details.
- Autocompletion is available via `Tab`.

---

## Plugins

- Place plugin commands in `plugins/<category>/entrypoint.py`.
- Use `@command(...)` decorator or export `COMMAND` / `COMMANDS`.
- Every command must define a `category` with description and example.
- Optional argument completers enhance user experience.

Refer to [Plugin Development Guide](plugins.md) for full instructions.

---

## Security

- File operations are sandboxed within the secure workspace.
- Path sanitization enforced for `Path`-typed parameters and decorated paths.
- Windows-specific hardening includes ACLs, EFS encryption, and TEMP/TMP isolation.
- Registry synced to SQLite for persistence.

See [Security Model](security.md) for full details.

---

## Developer Guide

- Follow **PEP-8** and Google-style docstrings.
- Keep commands small and modular; the shell handles chaining, piping, and redirects.
- Return either a string, `None`, or `CommandResult` from commands.
- Use type hints for safe argument coercion and workspace sandboxing.

See [Architecture Guide](architecture.md) for details on modules and interactions.

---

## Architecture

**core/boot/** – Startup, environment detection, workspace resolution, DB initialization, command loading.  
**core/commands/** – Command definitions, registry, decorators.  
**core/db/** – SQLite persistence for commands and workspaces.  
**core/helpers/** – System info collection.  
**core/interface/** – CLI frontends, input handling, parser, autocompletion, dispatching.  
**core/security/** – Secure workspace model, path resolution, Windows hardening.  
**core/ui/** – Terminal output utilities: ANSI colors, tables, logging, spinners, progress bars.

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

4. Implement changes with tests and docstrings.
5. Push to your fork and create a pull request.

---

## License

MIT License © 2025 [sx-kaos](https://github.com/sx-kaos/lunar-terminal)

---

## Logo Placeholder

![Lunar Terminal Logo](docs/logo.png)

