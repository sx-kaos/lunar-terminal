# Plugin Development Guide

This guide explains how to build, package, and ship **plugins** for *Lunar Terminal*. It covers the loader rules (`entrypoint.py`), the command API, completion hooks, argument parsing rules, workspace security, and best‑practices.

> **TL;DR**
> - Put each plugin’s commands in an **`entrypoint.py`** file, under the commands package (default: `plugins/`).
> - **Every command must declare a `category`.**
> - Register commands using the `@command(...)` decorator **or** export `COMMAND` / `COMMANDS` (instances of `Command`) from `entrypoint.py`.
> - Use the provided arg binder (`key=value`, positional args) and **path sandboxing** helpers.
> - Return either a plain string **or** a `CommandResult`.

---

## 1) Where plugins live

The loader scans the **commands package** defined by config environment variables:

- `PLUGIN_PATH` → defaults to `plugins`

Folder layout (recommended, category-first):

```
plugins/
└─ recon/    # category package (recommended)
    ├─ src/
    ├─ src/traceroute.py                # source code for command - called in entrypoint.py
    ├─ __init__.py                  # optional; its docstring can describe the category
    └─ entrypoint.py                # <<< put your command objects here
```

> The loader searches for **`entrypoint.py`** in each subpackage and imports it. Your `entrypoint.py` must either **decorate** functions (so they auto-register) or **export** `COMMAND` or `COMMANDS` containing `Command` instances.

### Category descriptions
When the loader sees `plugins/<category>`, it will optionally populate the help text for that category from either:
- `plugins/<category>/CATEGORY_DESCRIPTION` (a string), or
- the **module docstring** of `plugins/<category>/__init__.py`.

This text shows up in the `help` overview table.

---

## 2) Command API (core types)

From `core.commands.command_types` and `core.commands.commands`:

### `CommandResult`
```py
@dataclass(slots=True)
class CommandResult:
    ok: bool = True
    message: str = ""
    data: Any = None

    def __str__(self) -> str: ...
```
Return this when you want structured status + a printable message. If you return a **string** instead, the shell prints it directly. If you return **`None`**, nothing is printed.

### `Command`
```py
@dataclass(slots=True)
class Command:
    name: str
    description: str
    example: str
    callback: CommandCallback
    id: int | None = None
    module: str = ""
    category: str = "general"               # ← REQUIRED for your plugins
    completers: Mapping[str, Callable[..., object]] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    param_names: list[str] = field(default_factory=list)

    def invoke(self, *args, **kwargs) -> Any: ...
```
> **Note:** the `id` is filled by the DB sync step on boot (`sync_registry_to_database`).

### Decorator: `@command(...)`
```py
from core.commands import command

@command(
    name: str | None = None,               # default: function_name -> kebab-case
    description: str | None = None,        # default: function docstring
    example: str | None = None,
    id: int | None = None,
    category: str | None = None,           # ← set this explicitly
    completers: Mapping[str, Callable[..., object]] | None = None,
    aliases: list[str] | None = None,
)
def your_func(...): ...
```
The decorator:
- **Registers** the function as a CLI command in the global registry.
- Infers `param_names` from the Python signature (used by completion).
- Converts `snake_case` function names to `kebab-case` by default.

### Manual registration (optional)
```py
from core.commands import register_command, Command

register_command(Command(...))
```
This is useful when you build commands programmatically (e.g., from config) or need custom wiring before registering.

---

## 3) Required `entrypoint.py`

Your plugin must expose commands through an `entrypoint.py`. You can use either pattern below.

### A) Decorator pattern (recommended)
`plugins/recon/entrypoint.py`
```py
from __future__ import annotations
from pathlib import Path

from core.commands import command, CommandResult
from core.security import sandbox_paths

@command(
    description="Perform a traceroute on a host and save the results.",
    example="traceroute google.com output.txt",
    category="recon",                    # ← REQUIRED
    aliases=["tr"],
    completers={
        "host": lambda text, **_: [],     # you can provide real suggestions
        "output": lambda text, **_: [],
    },
)
@sandbox_paths("output")                 # ensure writes stay in workspace
def traceroute(*, url: str, output: Path) -> CommandResult:
    # (Pseudo-logic) download bytes, write to output
    output.write_text("demo traceroute", encoding="utf-8")
    return CommandResult(ok=True, message=f"Saved to {output}")

@command(description="Echo args or piped input.", category="recon", example="echo hello")
def echo(*args: str, stdin: str | None = None) -> str:
    return " ".join(args) if args else (stdin or "")
```

### B) Export `COMMAND/COMMANDS`
`plugins/recon/entrypoint.py`
```py
from __future__ import annotations
from core.commands import Command
from mylib import my_callback

COMMAND = Command(
    name="mycmd",
    description="Runs my custom callback.",
    example="mycmd foo=bar",
    callback=my_callback,
    category="recon",                 # ← REQUIRED
    aliases=["mc"],
)
# or:
# COMMANDS = [Command(...), Command(...), ...]
```

> The loader imports `entrypoint.py` and, if `COMMAND`/`COMMANDS` exist and are instances of `Command` (or an iterable of them), it registers them for you.

---

## 4) Arguments & binding rules

The shell uses `core.interface.parser.bind_args` to map CLI tokens to your function signature:

- **Positional** arguments become positional parameters.
- **Key-value** tokens (`key=value`) map to keyword parameters.
- `*args` are supported and will receive any remaining positionals.
- **Booleans** accept: `1, true, yes, y, on` (case-insensitive).
- Type coercion is applied from **annotations**:
  - `int`, `float`, `bool`, `str`, `Any`
  - `pathlib.Path` / `os.PathLike` and **containers of Paths** are sanitized (see security below).
- Missing required params raise a usage error (the shell prints a friendly usage string).

**Usage** strings are generated from your function signature (see `build_usage`), e.g.:
```
scan <host> [port] [timeout=...] [args...]
```

### Receiving piped input
If users run `foo | bar`, the framework tries to inject the left output into the right command by:
1. Matching common parameter names: `stdin`, `_in`, `input`, `data`, `text`, `content`, `payload`, `body`; **or**
2. Appending to `*args` if present.

Example:
```py
@command(description="Uppercase piped text.", category="utils")
def upper(stdin: str | None = None) -> str:
    return (stdin or "").upper()
```

---

## 5) Completions

Each command can supply **completers**: a mapping of keys to callables that return candidate strings.

Keys:
- **Named params**: `"name"`, `"output"`, etc. (displayed as `name=` suggestions)
- **Positional** indexes: `"pos0"`, `"pos1"`, ...
- **Wildcard positional**: `"pos*"` (for all positions)

Provider signature (duck-typed):
```py
def provider(*, text: str, argv: list[str], index: int | None) -> Iterable[str]:
    ...
```
- `text` → current prefix being completed
- `argv` → the argument tokens typed so far (excluding the command name)
- `index` → the positional index for `posN`, else `None`

Example:
```py
def port_suggest(*, text, **_):
    return [p for p in ("22","80","443","8080") if p.startswith(text)]

@command(description="Scan a host.", category="recon",
         completers={"host": lambda text, **_: [], "port": port_suggest, "pos0": lambda text, **_: ["localhost"]})
def scan(*, host: str, port: int = 80) -> str:
    return f"Scanned {host}:{port}"
```

The global completion engine also suggests:
- Built-ins: `help`, `exit`, `quit`, `clear`, `cls`
- All **command names** and **aliases**
- For `help <...>`: **category** names + command names

---

## 6) Security & the workspace sandbox

All file operations must stay inside the **active secure workspace**. The framework enforces this in several ways:

- The **argument binder** auto-sanitizes values annotated as `Path` / `PathLike` (including containers) **or** whose parameter names look path-like (`PATHY_KEYS`: `"path"`, `"file"`, `"dir"`, `"output"`, etc.).
- You can force sanitation with the decorator:
  ```py
  from core.security import sandbox_paths

  @command(..., category="files")
  @sandbox_paths("src", "dst")
  def cp(*, src: Path, dst: Path) -> str: ...
  ```
- To sanitize manually:
  ```py
  from core.security import sanitize_path, resolve_in_sandbox
  safe = sanitize_path(user_value)   # returns a safe Path inside the workspace
  ```
- On Windows, traversal through **reparse points** (junctions/symlinks) is blocked.
- Redirections (`>`, `>>`) are resolved inside the workspace automatically.

> If your command writes files, **always** accept `Path`-typed parameters or decorate with `@sandbox_paths(...)` so users cannot escape the workspace.

---

## 7) Returning output

Your command may return:
- `None` → prints nothing
- `str`  → printed to the console (subject to chaining/redirects)
- `CommandResult` → normalized status with an optional message and data payload

Examples:
```py
@command(description="Returns nothing visible.", category="demo")
def silent() -> None:
    return None

@command(description="Plain text.", category="demo")
def hello(name: str = "world") -> str:
    return f"hello {name}"

@command(description="Structured result.", category="demo")
def whoami() -> CommandResult:
    import getpass, platform
    return CommandResult(
        ok=True,
        message=f"{getpass.getuser()}@{platform.node()}",
        data={"user": getpass.getuser()},
    )
```

---

## 8) Chaining, piping, and redirection

The shell supports:
- `cmd1 && cmd2` → run `cmd2` only if `cmd1` **succeeded** (no `[error]` prefix)
- `cmd1 || cmd2` → run `cmd2` only if `cmd1` **failed**; `cmd1`’s output is piped to `cmd2`
- `cmd1 |  cmd2` → pipe stdout of `cmd1` into `cmd2`
- `cmd  > file`  → redirect to file (truncate)
- `cmd >> file`  → redirect to file (append)

All redirected paths are sandbox‑resolved (`resolve_in_sandbox`).

---

## 9) Category & help integration

**Every command must set a `category`.** Help views group by category:

- `help` → overview table: categories, counts, descriptions
- `help <category>` → commands within that category (+ aliases)
- `help <command>` → full detail: usage, example, id, etc.

To **describe a category**, place a docstring or `CATEGORY_DESCRIPTION` in `plugins/<category>/__init__.py`:

```py
"""Active reconnaissance and discovery commands (port scans, banners, etc.)."""
CATEGORY_DESCRIPTION = "Reconnaissance tools and scanners."
```

---

## 10) Environment & boot interactions

On boot the system:
1. Loads config (`PLUGIN_PATH`, workspace/log settings).
2. Locates and imports the commands package.
3. Imports every module / `entrypoint.py` under that package.
4. Warms completion (names + categories).
5. **Syncs the registry to SQLite** (`commands` table) and backfills `Command.id` where possible.

This means you can list all commands from the DB, correlate telemetry, or ship external UIs that reference command IDs.

---

## 11) Testing your plugin

- Start the terminal (from the project root) and watch the boot logs:
  - “Locate commands package 'plugins'”
  - “Discover command modules …”
- Run `help` to see categories and counts.
- Run `help <your-command>` to verify description, usage, and example.
- Verify **completion**:
  - Type your command name and press `Tab`.
  - For `key=value` parameters, ensure suggestions appear if you provided completers.
- Test **piping/redirects**:
  ```sh
  echo hello | your-command
  your-command > out.txt
  ```

---

## 12) Best practices checklist

- [ ] Place commands in `entrypoint.py` under the **commands package**.
- [ ] Set a **`category`** for every command.
- [ ] Write clear, user‑facing **`description`** and one‑line **`example`**.
- [ ] Prefer **type hints** (especially for `Path`) to unlock safe coercion.
- [ ] Use `@sandbox_paths(...)` or `sanitize_path` for any file I/O.
- [ ] Add **aliases** sparingly; avoid collisions with existing names.
- [ ] Provide **completers** for ergonomic `key=value` inputs.
- [ ] Return `CommandResult` for structured success/failure.
- [ ] Keep functions small; allow the shell to handle chaining and redirects.
- [ ] Add a module docstring or `CATEGORY_DESCRIPTION` to describe your category.

---

## 13) Minimal reference: imports you’ll use

```py
# Registration
from core.commands import command, register_command, Command, CommandResult

# Completion typing (providers are duck-typed)
from typing import Iterable

# Path safety & sandbox
from pathlib import Path
from core.security import (
    sanitize_path,
    sandbox_paths,
    resolve_in_sandbox,
    PATHY_KEYS,          # names treated as path-like by the binder
    is_path_annotation,  # utility if you reflect on annotations
)
```

Happy hacking! If you want an example starter plugin scaffold, copy the decorator pattern above, drop it into `plugins/<category>/entrypoint.py`, and iterate.
