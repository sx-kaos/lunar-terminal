# Plugin Development Guide

Lunar Terminal supports a flexible **plugin system** for extending commands.  
Plugins are Python modules that register commands into the global registry and are loaded at runtime.

---

## How Plugins Are Discovered

- The terminal searches the **commands package** (default: `plugins/`).
- Any module under this package is imported automatically at startup.
- If a module is a **subpackage** and contains an `entrypoint.py` file, that file is imported.
- `entrypoint.py` should define one or more **Command objects** or use the `@command` decorator.

---

## Command Registration Methods

There are two primary ways to register commands:

### 1. Using the `@command` Decorator

```python
# plugins/example/entrypoint.py
from core.commands import command

@command(
    name="hello",
    description="Say hello",
    example="hello --name Alice",
    category="general",
)
def hello(*, name: str = "world") -> str:
    return f"Hello, {name}!"
```

- This registers a `hello` command in the `general` category.
- Usage: `hello --name Alice`

### 2. Registering Command Objects Explicitly

```python
# plugins/example/entrypoint.py
from core.commands import Command, register_command

def greet(name: str) -> str:
    return f"Hi, {name}!"

COMMAND = Command(
    name="greet",
    description="Simple greeting command",
    example="greet Alice",
    callback=greet,
    category="demo",
)
register_command(COMMAND)
```

- Exposes a single command named `greet`.
- Usage: `greet Alice`

You can also expose multiple commands:

```python
COMMANDS = [COMMAND1, COMMAND2, ...]
```

---

## Command Metadata

Each `Command` object supports:

- `name`: Primary unique command name (auto kebab-cased from function name if using decorator).
- `description`: Short description shown in help.
- `example`: One-line usage example.
- `callback`: Python function implementing the command.
- `category`: Logical category for grouping in help output.
- `aliases`: Alternative names.
- `param_names`: Auto-detected parameter names (used for completion).
- `completers`: Optional suggestion providers for arguments.

---

## Help and Usage

The interface provides:

- `help` → lists all categories
- `help <category>` → lists commands in a category
- `help <command>` → shows detailed usage, aliases, example, and parameters

Example:

```text
> help hello

Name:        hello
Aliases:     (none)
Category:    general
ID:          (unassigned)
Description: Say hello
Example:     hello --name Alice
Usage:       hello [name]
```

---

## Development Tips

- Keep each plugin self-contained in a folder under `plugins/`.
- Use `entrypoint.py` to expose commands (`COMMAND`, `COMMANDS`, or decorated functions).
- Categories are auto-assigned from subpackage names if not specified.
- Command registry can sync to the SQLite catalog if enabled in config.
- Use `CommandResult` instead of raw strings for structured return values.

Example:

```python
from core.commands import command, CommandResult

@command(name="whoami", description="Show current user", category="system")
def whoami() -> CommandResult:
    import getpass
    return CommandResult(ok=True, message=getpass.getuser())
```

---

## Next Steps

- Explore built-in commands under `core/commands/` and `plugins/`.
- Use structured `CommandResult` where possible for consistency.
- Write unit tests for your plugins to ensure stability.
