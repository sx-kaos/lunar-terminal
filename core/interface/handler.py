#!/usr/bin/env python3
# core/interface/handler.py
from __future__ import annotations

"""
Command dispatch and help formatting, with shell-like chaining.

Supported operators:
  &&  - run next command only if previous succeeded
  >   - redirect previous command output (truncate)
  >>  - redirect previous command output (append)
  |   - pipe previous output into next command
  ||  - run next command only if previous failed, piping previous output
"""

import difflib
import shlex
from typing import List, Tuple

from core.commands import REGISTRY, CommandResult
from core.interface import tokenize, bind_args, build_usage
from core.ui import clear_screen, print_table
from core.security import resolve_in_sandbox

# Short hint shown at startup and used in unknown command errors
HELP_TEXT = "Type 'help <command>' for more information on a specific command."

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_OPERATORS = {"&&", "||", ">>", ">", "|"}


def _suggest_similar_names(name: str) -> str:
    """Return a short suggestion string for misspelled commands."""
    universe = REGISTRY.names() + ["help", "exit", "quit"]
    matches = difflib.get_close_matches(name, universe, n=3, cutoff=0.6)
    return f" Did you mean: {', '.join(matches)}?" if matches else ""


def _format_categories_table() -> str | None:
    """Render the categories overview table."""
    categories = REGISTRY.categories()
    if not categories:
        return "No commands loaded."

    rows = []
    for category_name in sorted(categories):
        command_count = len(categories[category_name])
        description_text = REGISTRY.get_category_description(category_name)
        rows.append(
            [category_name,
             f"{command_count} command{'s' if command_count != 1 else ''}",
             description_text]
        )
    return print_table(rows, headers=["Category", "Commands", "Description"])


def _format_category_help(category: str) -> str | None:
    """Render the commands table for a specific category."""
    categories = REGISTRY.categories()
    commands_in_category = categories.get(category)
    if not commands_in_category:
        return f"No such category: {category}"

    rows = []
    for command_obj in sorted(commands_in_category, key=lambda x: x.name.lower()):
        alias_display = ", ".join(
            command_obj.aliases) if command_obj.aliases else "-"
        rows.append([command_obj.name, alias_display, command_obj.description])

    return print_table(rows, headers=["Command", "Aliases", "Description"])


def format_command_help(name: str) -> str | None:
    """Render help for a command or a category if the name matches a category."""
    command_obj = REGISTRY.get(name)
    if not command_obj:
        categories = REGISTRY.categories()
        if name in categories:
            return _format_category_help(name)
        if name == 'all':  # Just list all commands
            for category in categories:
                _format_category_help(category)
            # Can't return None, just return empty string instead :shrug:
            return ''
        return f"No such command or category: {name}"

    usage_string = build_usage(command_obj.name, command_obj.callback)
    alias_text = ", ".join(command_obj.aliases) if getattr(
        command_obj, "aliases", ()) else "(none)"
    lines = [
        f"Name:        {command_obj.name}",
        f"Aliases:     {alias_text}",
        f"Category:    {command_obj.category}",
        f"ID:          {command_obj.id if command_obj.id is not None else '(unassigned)'}",
        f"Description: {command_obj.description or '(none)'}",
        f"Example:     {command_obj.example or '(none)'}",
        f"Usage:       {usage_string}",
    ]
    return "\n".join(lines)


def list_categories() -> str | None:
    """Return formatted category listing."""
    return _format_categories_table()

# ---------------------------------------------------------------------------
# Chaining / parsing helpers
# ---------------------------------------------------------------------------


def _lex_with_ops(line: str) -> list[str]:
    """
    Tokenize a line into tokens while keeping operators as separate tokens.

    Strategy:
      1) Try shlex with punctuation_chars in the constructor (Py 3.6+; read-only on 3.11+).
      2) Fallback: shlex.split for words, then split any tokens that contain operator chars.
    """
    try:
        # Python 3.11/3.12: punctuation_chars must be passed in the constructor.
        lex = shlex.shlex(line, posix=True, punctuation_chars="&|>")
        lex.whitespace_split = True
        lex.commenters = ""
        raw = list(lex)
    except TypeError:
        # Older Python: no ctor arg -> fallback path that preserves quotes.
        raw_words = shlex.split(line, posix=True)
        raw = []
        for word in raw_words:
            # Split embedded operators inside this word (e.g., 'foo&&bar' or '>>file')
            i = 0
            while i < len(word):
                ch = word[i]
                if ch in "&|>":
                    # Look ahead one char to form multi-char ops.
                    nxt = word[i + 1] if i + 1 < len(word) else ""
                    if ch == "&" and nxt == "&":
                        raw.append("&&")
                        i += 2
                        continue
                    if ch == "|" and nxt == "|":
                        raw.append("||")
                        i += 2
                        continue
                    if ch == ">" and nxt == ">":
                        raw.append(">>")
                        i += 2
                        continue
                    raw.append(ch)
                    i += 1
                    continue
                # accumulate a normal substring until next operator
                j = i
                while j < len(word) and word[j] not in "&|>":
                    j += 1
                raw.append(word[i:j])
                i = j

    # Coalesce any single-char pieces into multi-char operators if needed.
    out: list[str] = []
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok in {"&", "|", ">"} and (i + 1) < len(raw):
            nxt = raw[i + 1]
            if tok == "&" and nxt == "&":
                out.append("&&")
                i += 2
                continue
            if tok == "|" and nxt == "|":
                out.append("||")
                i += 2
                continue
            if tok == ">" and nxt == ">":
                out.append(">>")
                i += 2
                continue
        out.append(tok)
        i += 1
    return out


def _split_pipeline(tokens: List[str]) -> List[List[str]]:
    """
    Split into command 'segments' separated by control or pipe/redir operators,
    but keep the operators as their own single-item segments.

    Example:
        ["whoami", ">>", "perms.txt", "&&", "ws-list"]
    ->  [["whoami"], [">>"], ["perms.txt"], ["&&"], ["ws-list"]]
    """
    segments: List[List[str]] = []
    cur: List[str] = []
    for t in tokens:
        if t in _OPERATORS:
            if cur:
                segments.append(cur)
                cur = []
            segments.append([t])
        else:
            cur.append(t)
    if cur:
        segments.append(cur)
    return segments


def _write_redirect(path: str, data: str, append: bool) -> None:
    """Write redirected output (UTF-8) with either truncate or append semantics."""
    # Always resolve inside current workspace
    target = resolve_in_sandbox(path)  # NEW
    mode = "a" if append else "w"

    # Ensure parent exists (still within workspace thanks to resolve_in_sandbox)
    target.parent.mkdir(parents=True, exist_ok=True)

    with open(target, mode, encoding="utf-8", newline="") as f:
        f.write(data)


def _is_success(output: str | None) -> bool:
    """
    Success = no error marker. Accept both [ERROR] and [error] (case-insensitive).
    Treat None as success.
    """
    if output is None:
        return True
    lead = output.lstrip()
    return not lead.lower().startswith("[error]")


def _inject_stdin(positional, keywords, func, stdin: str) -> Tuple[Tuple, dict]:
    import inspect
    sig = inspect.signature(func)
    params = sig.parameters

    # Try common stdin-style parameter names (priority order)
    for name in ("stdin", "_in", "input", "data", "text", "content", "payload", "body"):
        if name in params:
            kw = dict(keywords)
            kw[name] = stdin
            return positional, kw

    # If the command accepts *args, append as a positional
    if any(p.kind is p.VAR_POSITIONAL for p in params.values()):
        return tuple([*positional, stdin]), dict(keywords)

    # No safe place to inject -> drop the pipe (don't break the call)
    return positional, keywords

# ---------------------------------------------------------------------------
# Core execution
# ---------------------------------------------------------------------------


def _run_single_command(input_line: str, stdin_data: str | None = None) -> Tuple[str | None, bool]:
    """
    Run a single command (no operators). Returns (output, success).
    This is a refactor-friendly extraction of the original dispatch path.
    """
    line = input_line.strip()
    if not line:
        return None, True

    lowered = line.lower()
    if lowered in {"exit", "quit"}:
        raise SystemExit()

    if lowered in {"clear", "cls"}:
        clear_screen()
        return None, True

    if lowered == "help":
        return list_categories(), True

    if lowered.startswith("help "):
        _, _, target = line.partition(" ")
        return format_command_help(target.strip()), True

    # Dispatch to a registered command
    tokens = tokenize(line)
    command_name, *arg_tokens = tokens
    command_obj = REGISTRY.get(command_name)
    if not command_obj:
        msg = f"Unknown command: {command_name}.{_suggest_similar_names(command_name)} {HELP_TEXT}"
        return msg, False

    try:
        positional_args, keyword_args = bind_args(
            command_obj.callback, arg_tokens)

        # Pipe stdin if requested/available
        if stdin_data is not None and stdin_data != "":
            positional_args, keyword_args = _inject_stdin(
                positional_args, keyword_args, command_obj.callback, stdin_data
            )

        result = command_obj.invoke(*positional_args, **keyword_args)

        # Normalize output
        if isinstance(result, CommandResult):
            text = None if result.message == "" else str(result)
            return text, _is_success(text)
        text = None if result is None else str(result)
        return text, _is_success(text)

    except SystemExit:
        raise
    except TypeError as exc:
        usage = build_usage(command_obj.name, command_obj.callback)
        return f"[error] {exc}\nUsage: {usage}", False
    except Exception as exc:
        return f"[error] {type(exc).__name__}: {exc}", False


def handle_line(input_line: str) -> str | None:
    """
    Parse and execute a (possibly chained) input line.

    Returns:
        - None if nothing should be printed.
        - A printable string (the last non-redirected output).
    """
    # Fast path: no operators - keep old behavior
    if not any(op in input_line for op in ("&&", "||", "|", ">>", ">")):
        out, _ok = _run_single_command(input_line)
        return out

    tokens = _lex_with_ops(input_line)
    segments = _split_pipeline(tokens)

    last_output: str | None = None
    last_visible_output: str | None = None
    last_success = True
    i = 0

    # Walk: [cmd] [op] [cmd] [redir] [file] [op] [cmd] ...
    while i < len(segments):
        seg = segments[i]
        if not seg:
            i += 1
            continue

        # Operator segments apply to the NEXT command
        if len(seg) == 1 and seg[0] in _OPERATORS:
            op = seg[0]
            at_start = (i == 0)
            at_end = (i == len(segments) - 1)
            next_is_op = (not at_end and len(
                segments[i + 1]) == 1 and segments[i + 1][0] in _OPERATORS)
            if at_start:
                return f"[error] Syntax: operator '{op}' missing left-hand command."
            if at_end or next_is_op:
                return f"[error] Syntax: operator '{op}' missing right-hand command."
            i += 1
            continue

        # Rebuild command text while PRESERVING quotes
        cmd_text = shlex.join(seg)

        # Detect immediate redirection after this command
        redir_mode: str | None = None   # ">" or ">>"
        redir_target: str | None = None
        j = i + 1
        if j < len(segments) and len(segments[j]) == 1 and segments[j][0] in {">", ">>"}:
            redir_mode = segments[j][0]
            j += 1
            if j >= len(segments) or (len(segments[j]) == 1 and segments[j][0] in _OPERATORS):
                return "[error] Syntax: redirection requires a filename."
            # Filename segment is already tokenized; join its tokens as a literal path string
            redir_target = " ".join(segments[j])
            j += 1

        # Determine operator BEFORE this command
        prev_op = segments[i - 1][0] if i > 0 and len(
            segments[i - 1]) == 1 and segments[i - 1][0] in _OPERATORS else None

        # Determine operator AFTER this command (used to optionally suppress visible output on pipe)
        next_idx = j if redir_mode else (i + 1)
        next_op = segments[next_idx][0] if next_idx < len(segments) and len(
            segments[next_idx]) == 1 and segments[next_idx][0] in _OPERATORS else None

        # Control flow + piping
        run_now = True
        stdin_for_this: str | None = None
        if prev_op == "&&" and not last_success:
            run_now = False
        elif prev_op == "||":
            run_now = not last_success
            if run_now:
                stdin_for_this = last_output or ""
        elif prev_op == "|":
            stdin_for_this = last_output or ""

        if run_now:
            out, ok = _run_single_command(cmd_text, stdin_for_this)
            last_output = out if out is not None else ""
            last_success = ok

            # Redirection handling
            if redir_mode and redir_target:
                try:
                    _write_redirect(redir_target, last_output,
                                    append=(redir_mode == ">>"))
                except Exception as exc:
                    last_output = f"[error] {type(exc).__name__}: {exc}"
                    last_success = False
                    last_visible_output = last_output  # show redirection error
                else:
                    last_visible_output = None  # suppressed because redirected
            else:
                # No redirection - potentially visible
                last_visible_output = last_output if (
                    last_output or last_output == "") else None

            # If the next operator is a pipe, suppress visible output for this stage
            if next_op == "|":
                last_visible_output = None
        else:
            # Skipped due to && / || conditions
            last_visible_output = None

        # Advance index past command (+ optional redirection pair)
        i = j if redir_mode else (i + 1)

    return last_visible_output
