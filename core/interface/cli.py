#!/usr/bin/env python3
# core/interface/cli.py
from __future__ import annotations

"""
Interactive input frontends.

Selection order:
    1) prompt_toolkit (rich completion + history)
    2) readline / pyreadline3 (basic completion + history)
    3) plain input (last resort)
"""

import ctypes
import getpass
import os
import platform
from pathlib import Path
from typing import Optional
from core.interface import suggest

# History location in the user home directory (readable name across OSes)
HISTORY_FILE_PATH = Path.home() / ".history"


def _is_admin_user() -> bool:
    """
    Heuristically check if the current process has admin/root privileges.
    Windows: IsUserAnAdmin via shell32
    POSIX:   euid == 0
    """
    if platform.system() == "Windows":
        try:
            # type: ignore[attr-defined]
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        # On platforms without geteuid (e.g., Windows), best effort only.
        return False


class BaseCLI:
    """
    Base interface for CLI frontends.

    Subclasses should implement:
        - setup()
        - get_line()
        - teardown()

    This base also provides context manager support to guarantee teardown.
    """

    def setup(self) -> None:  # pragma: no cover - interface
        ...

    def get_line(self) -> str:  # pragma: no cover - interface
        ...

    def teardown(self) -> None:  # pragma: no cover - interface
        ...

    # Context manager helpers
    def __enter__(self) -> "BaseCLI":
        self.setup()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.teardown()
        except Exception:
            pass


# ===== Preferred: prompt_toolkit =====
class PromptToolkitCLI(BaseCLI):
    """Rich line editor with history and live completion."""

    def __init__(self) -> None:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.key_binding import KeyBindings
        # reuse the same token logic as completion.suggest uses
        from core.interface.completion import _split_current_token

        self._prompt = prompt
        self._history = FileHistory(str(HISTORY_FILE_PATH))
        self.username_display = "root" if _is_admin_user() else getpass.getuser() or "user"

        class _Completer(Completer):
            def get_completions(self, document, complete_event):
                text_before_cursor = document.text_before_cursor
                # compute the current token prefix using shlex-splitting
                _, current_prefix = _split_current_token(text_before_cursor)
                replace_len = len(current_prefix)
                for word in suggest(text_before_cursor):
                    # replace exactly the current token (prevents ws-l-ws-list concatenation)
                    yield Completion(word, start_position=-replace_len)

        self._completer = _Completer()

        # Key bindings to trigger completion when deleting characters.
        kb = KeyBindings()

        @kb.add("backspace")
        def _(event):
            b = event.app.current_buffer
            if b.read_only():
                return
            if b.selection_state:
                b.delete_selection()
            else:
                b.delete_before_cursor(1)
            # show fresh suggestions after deletion
            b.start_completion(select_first=False)

        @kb.add("delete")
        def _(event):
            b = event.app.current_buffer
            if b.selection_state:
                b.delete_selection()
            else:
                b.delete(1)
            b.start_completion(select_first=False)

        self._key_bindings = kb

        def setup(self) -> None:
            HISTORY_FILE_PATH.touch(exist_ok=True)

    def get_line(self) -> str:
        prompt_prefix = f"[{self.username_display}@{platform.node()}]:~# "
        return self._prompt(
            prompt_prefix,
            history=self._history,
            completer=self._completer,
            complete_while_typing=True,   # suggestions while typing (inserts)
            key_bindings=self._key_bindings,  # suggestions when deleting
        )

    def teardown(self) -> None:
        # prompt_toolkit flushes history automatically
        pass


# ===== Fallback: readline / pyreadline3 =====
class ReadlineCLI(BaseCLI):
    """Fallback editor with basic completion and history."""

    def __init__(self) -> None:
        import readline  # type: ignore[attr-defined]

        self.readline = readline

    def setup(self) -> None:
        HISTORY_FILE_PATH.touch(exist_ok=True)
        try:
            self.readline.read_history_file(  # type: ignore
                str(HISTORY_FILE_PATH))
        except OSError:
            pass

        # Allow '=' as part of tokens to support key=value completion
        try:
            self.readline.set_completer_delims(" \t\n")  # type: ignore
        except Exception:
            pass

        def _complete(text_fragment: str, state_index: int) -> Optional[str]:
            # Build the entire line buffer and return the Nth suggestion
            buffer_text = self.readline.get_line_buffer()  # type: ignore
            candidates = suggest(buffer_text)
            matches = [
                word for word in candidates if word.startswith(text_fragment)]
            return matches[state_index] if state_index < len(matches) else None

        self.readline.set_completer(_complete)  # type: ignore
        try:
            self.readline.parse_and_bind("tab: complete")  # type: ignore
        except Exception:
            pass

    def get_line(self) -> str:
        return input("> ")

    def teardown(self) -> None:
        try:
            self.readline.write_history_file(  # type: ignore
                str(HISTORY_FILE_PATH))
        except OSError:
            pass


def make_cli() -> BaseCLI:
    """
    Factory to select the best available CLI frontend at runtime.
    """
    # Try prompt_toolkit first
    try:
        import prompt_toolkit  # noqa: F401
        return PromptToolkitCLI()
    except Exception:
        # Try readline/pyreadline3
        try:
            import readline  # noqa: F401
            return ReadlineCLI()
        except Exception:
            # Last resort: plain input with no completion or history
            return BaseCLI()  # type: ignore[return-value]
