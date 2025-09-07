#!/usr/bin/env python3
# core/interface/parser.py
from __future__ import annotations

"""
Argument parsing helpers for commands.

Responsibilities:
- Tokenize a command line into shell-like tokens.
- Bind tokens to a callable signature with type coercion based on annotations.
- Render compact Usage strings from a function signature.
"""

import inspect
import os
import shlex
from pathlib import Path
from typing import Any, get_args, get_origin

# NEW: centralized sandbox sanitization
from core.security import sanitize_path, PATHY_KEYS, is_path_annotation


def tokenize(command_line: str) -> list[str]:
    """Split a raw command line into tokens using POSIX rules."""
    return shlex.split(command_line, posix=True)


def _coerce_value(text_value: str, annotation: Any) -> Any:
    """
    Convert a string to the annotated type when reasonable.

    Supported coercions:
        - str/Any/inspect._empty -> original text
        - bool -> accepts '1,true,yes,y,on' (case-insensitive)
        - int/float -> cast via constructor
        - pathlib.Path / os.PathLike -> sanitized Path inside sandbox
        - Tuple[List][Path,...] -> element-wise sanitize
    """
    # Path-like annotations -> sanitize immediately
    if is_path_annotation(annotation):
        # Element container handling
        origin = get_origin(annotation)
        if origin in (list, tuple, set):
            # Split CSV only if the user actually provided commas; otherwise treat as single path token.
            items = [t.strip() for t in text_value.split(
                ",")] if "," in text_value else [text_value]
            sanitized = [sanitize_path(item) for item in items]
            return sanitized if origin is list else (tuple(sanitized) if origin is tuple else set(sanitized))
        # Single path-like
        return sanitize_path(text_value)

    if annotation in (inspect._empty, str, Any):
        return text_value
    if annotation is bool:
        lowered = text_value.lower()
        return lowered in ("1", "true", "yes", "y", "on")
    if annotation in (int, float):
        return annotation(text_value)
    # Fallback to original text for any other type
    return text_value


def _maybe_sanitize_by_name(param_name: str, value: Any) -> Any:
    """
    If a parameter looks path-like by name (PATHY_KEYS),
    sanitize even when annotation is 'str' or unspecified.
    """
    if param_name not in PATHY_KEYS:
        return value

    def _sanitize(v: Any) -> Any:
        if isinstance(v, (str, Path, os.PathLike)):
            return sanitize_path(v)
        if isinstance(v, (list, tuple, set)):
            t = type(v)
            return t(_sanitize(x) for x in v)
        return v

    return _sanitize(value)


def bind_args(func: Any, tokens: list[str]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """
    Bind a flat token list to the signature of `func`.

    Supports:
        - positional tokens
        - key=value tokens for keyword-only or normal parameters
        - *args (VAR_POSITIONAL) with optional element annotation via typing.Tuple[T, ...]
    """
    signature = inspect.signature(func)
    parameters = list(signature.parameters.values())

    positional_tokens: list[str] = []
    kw_tokens_raw: dict[str, str] = {}
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            kw_tokens_raw[key] = value
        else:
            positional_tokens.append(token)

    bound_positional: list[Any] = []
    bound_keywords: dict[str, Any] = {}
    positional_index = 0
    var_positional_name: str | None = None
    var_positional_annotation: Any = inspect._empty

    # First pass: positional parameters and detection of *args
    for parameter in parameters:
        if parameter.kind is parameter.VAR_POSITIONAL:
            var_positional_name = parameter.name
            var_positional_annotation = parameter.annotation
            continue

        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
            if positional_index < len(positional_tokens):
                raw = positional_tokens[positional_index]
                value = _coerce_value(raw, parameter.annotation)
                # Name-based safety net (for str-typed paths)
                value = _maybe_sanitize_by_name(parameter.name, value)
                bound_positional.append(value)
                positional_index += 1
            elif parameter.default is not inspect._empty:
                bound_positional.append(parameter.default)
            else:
                raise TypeError(f"Missing required argument: {parameter.name}")
        elif parameter.kind is parameter.KEYWORD_ONLY:
            if parameter.name in kw_tokens_raw:
                value = _coerce_value(
                    kw_tokens_raw[parameter.name], parameter.annotation)
                value = _maybe_sanitize_by_name(parameter.name, value)
                bound_keywords[parameter.name] = value
            elif parameter.default is inspect._empty:
                raise TypeError(
                    f"Missing required keyword-only argument: {parameter.name}")

    # Pack remaining positionals into *args
    if var_positional_name is not None:
        remaining = positional_tokens[positional_index:]
        element_annotation = str
        origin = get_origin(var_positional_annotation)
        args_ = get_args(var_positional_annotation) or ()
        if origin is tuple and args_:
            element_annotation = args_[0]

        values = [_coerce_value(item, element_annotation)
                  for item in remaining]
        # If *args param name looks like paths, sanitize regardless of annotation
        if var_positional_name in PATHY_KEYS:
            values = [sanitize_path(v) if isinstance(
                v, (str, Path, os.PathLike)) else v for v in values]

        bound_positional.extend(values)
        positional_index = len(positional_tokens)
    elif positional_index < len(positional_tokens):
        raise TypeError("Too many positional arguments.")

    # Map remaining kwargs for POSITIONAL_OR_KEYWORD params
    for parameter in parameters:
        if parameter.kind is parameter.POSITIONAL_OR_KEYWORD and parameter.name in kw_tokens_raw:
            value = _coerce_value(
                kw_tokens_raw[parameter.name], parameter.annotation)
            value = _maybe_sanitize_by_name(parameter.name, value)
            bound_keywords[parameter.name] = value

    return tuple(bound_positional), bound_keywords


def build_usage(command_name: str, func: Any) -> str:
    """
    Render a compact usage string based on `func` signature.

    Examples:
        'scan <host> [port] [timeout=...] [args...]'
    """
    signature = inspect.signature(func)
    usage_parts: list[str] = []

    for parameter in signature.parameters.values():
        if parameter.kind is parameter.VAR_POSITIONAL:
            usage_parts.append("[args...]")
            continue

        token = f"<{parameter.name}>" if parameter.default is inspect._empty else f"[{parameter.name}]"
        if parameter.kind is parameter.KEYWORD_ONLY:
            token = f"[{parameter.name}=...]"
        usage_parts.append(token)

    return f"{command_name} " + " ".join(usage_parts) if usage_parts else command_name
