# 🌙 Lunar Terminal

A secure, extensible **cybersecurity command-line environment** written in Python 3.10+.  
It provides a hardened workspace model, pluggable commands, intelligent completions, and Windows-friendly UI features such as colorized logging, spinners, and progress bars.

---

## ✨ Features

- **Secure Workspaces**
  - Auto-hardened per-session directories
  - Windows ACL tightening + optional EFS encryption
  - Sandbox path resolution (`resolve_in_sandbox`)
  - Workspace catalog stored in SQLite

- **Pluggable Command System**
  - Declarative `@command` decorator
  - Global registry (`REGISTRY`)
  - Dynamic plugin loader (`plugins/` package)
  - Categories + help/usage rendering
  - Token-aware argument binding (types, `key=value`, variadics)

- **Interactive REPL**
  - Tab-completion with context-aware suggestions
  - Command chaining (`&&`, `||`, pipes `|`, redirects `> >>`)
  - Built-in commands: `help`, `exit`, `clear`, etc.
  - Multiple CLI frontends (prompt_toolkit, readline, plain input)

- **System Info Helpers**
  - CPU/GPU/RAM/Kernel/Disk snapshot (Windows-friendly)
  - Zero external dependencies (ctypes + PowerShell CIM)

- **UI Utilities**
  - ANSI color utilities + rich-like markup
  - Progress bar + spinner widgets
  - Color-safe logging (ANSI/WinAPI fallback)
  - ASCII tables with ANSI-safe width handling

---

## 🛠️ Installation

```bash
git clone https://github.com/sx-kaos/lunar-terminal.git
cd lunar-terminal
python3 -m venv .venv
source .venv/bin/activate   # (or .venv\Scripts\activate on Windows)
pip install -r requirements.txt
```

> **Note**: The project avoids heavy deps. Core modules rely on stdlib.  
> Optional: `prompt_toolkit` for richer CLI.

---

## 🚀 Usage

Run the terminal:

```bash
python -m core.main
```

You’ll see a startup banner with system info and tips.  
From there you can type `help`, `help <category>`, or `help <command>`.

### Example Commands
```bash
ws-list              # list workspaces
dns-lookup example.com
whoami
```

Supports chaining:
```bash
dns-lookup example.com | grep 93.184
whoami && ws-list
```

---

## 📂 Project Structure

```
core/
 ├── boot/         # boot sequence & environment setup
 ├── commands/     # command registry, decorators, plugin interfaces
 ├── db/           # SQLite config + workspace catalog
 ├── helpers/      # system info collectors (CPU/GPU/RAM/etc.)
 ├── interface/    # REPL CLI, parser, handler, loader
 ├── security/     # secure workspace + path sanitization
 └── ui/           # utils, logging, tables, spinners, progress bar
plugins/           # user-defined command modules
main.py       # application entrypoint (REPL loop)
```

---

## ⚙️ Extending with Plugins

Plugins can be easily created and loaded into the terminal.
The core functions and other external functions can both be utilised. 

Example plugin:
```python
# plugins/example/entrypoint.py
from core.commands import command

@command(description="Say hello")
def hello(name: str = "world") -> str:
    return f"Hello, {name}!"
```

For more information on creating plugins see [the plugin documentation](github.com/sx-kaos/lunar-terminal/PLUGINS.md).

## 🔒 Security Model

- All file operations are sandboxed to the **active workspace**.
- Paths are validated against reserved device names (Windows).
- NTFS ADS (alternate data streams) are blocked.
- Workspaces can be switched, archived, or adopted.

---

## 📊 Development Status

- Current version: **4-dev**
- OS focus: **Windows 11**, but Linux/Mac supported with reduced hardening.
- Python: **3.10+**
- Lines of code: ~4.8k
- Functions/classes: 130+ with Google-style docstrings (in progress).

---

## 📜 License

MIT License © 2025 [sx-kaos](https://github.com/sx-kaos)
