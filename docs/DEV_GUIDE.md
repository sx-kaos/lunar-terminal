# Lunar Terminal Developer Guide

Welcome to the Lunar Terminal developer guide.  
This document is designed to help contributors, maintainers, and advanced users understand the internals of the project and extend its functionality.

---

## Overview

Lunar Terminal is built with a modular architecture that makes it easy to extend functionality with new commands, ensure safety through secure workspaces, and provide a smooth interactive user experience.

---

## Sections

- [Architecture](architecture.md)  
  Learn about the structure of the `core/` package, the responsibilities of each module, and how they work together.

- [Plugins](plugins.md)  
  How to develop and register new commands, package them as plugins, and use the `command` decorator or Command objects.

- [Security](security.md)  
  Secure workspace model, sandboxed path resolution, Windows ACL/EFS hardening, and how developers should work with file paths safely.

---

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/sx-kaos/lunar-terminal.git
   cd lunar-terminal
   ```

2. Create a virtual environment and install requirements:
   ```bash
   python -m venv venv
   source venv/bin/activate   # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

3. Run the terminal:
   ```bash
   python -m core.main
   ```

---

## Contribution Guidelines

- Follow **PEP-8** for style consistency.
- Use **Google-style docstrings** for functions and classes.
- Keep security considerations in mind: never bypass `sanitize_path` or `resolve_in_sandbox` when dealing with filesystem access.
- When adding new commands:
  - Prefer the `@command` decorator for simplicity.
  - Ensure every command has a description, example, and belongs to a category.
  - Use `CommandResult` when structured output is appropriate.

---

## Next Steps

- [Architecture Guide](architecture.md)  
- [Plugin Development Guide](plugins.md)  
- [Security Model](security.md)  

Each of these documents dives deeper into its subject matter.
