#!/usr/bin/env python3
# core/security/sanitize.py
from __future__ import annotations

from functools import wraps
from pathlib import Path
from typing import Any, Callable, get_args, get_origin
import os

from .secure_dir import resolve_in_sandbox

# Common parameter names that imply "this is a path"
PATHY_KEYS: set[str] = {
    "path", "paths", "src", "source", "dst", "dest", "destination",
    "file", "files", "folder", "dir", "directory", "output", "target",
}

# Block Windows NTFS ADS (e.g., "file.txt:stream") and reserved device names
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def _deny_ntfs_ads(p: Path) -> None:
    tail_parts = p.parts[1:] if p.drive else p.parts
    if any(":" in part for part in tail_parts):
        raise PermissionError("Alternate Data Streams are not allowed.")


def _deny_win_reserved(p: Path) -> None:
    stem = p.name.split(".")[0].lower()
    if stem in _WINDOWS_RESERVED:
        raise PermissionError(f"Reserved Windows name blocked: {p.name!r}")


def sanitize_path(user_path: str | os.PathLike[str] | Path) -> Path:
    """
    Resolve a user-supplied path strictly inside the active workspace,
    then apply extra Windows-specific checks.
    """
    p = resolve_in_sandbox(str(user_path))
    _deny_ntfs_ads(p)
    if p.name:
        _deny_win_reserved(p)
    return p


def is_path_annotation(annotation: Any) -> bool:
    """
    True if the type annotation indicates a filesystem path.
    Supports: pathlib.Path, os.PathLike, typing.Annotated[Path, ...],
    and tuples/lists of Path/PathLike.
    """
    if annotation is Path:
        return True
    if annotation is os.PathLike or getattr(annotation, "__name__", "") == "PathLike":
        return True
    origin = get_origin(annotation)
    if origin in (list, tuple, set):
        args = get_args(annotation)
        return any(is_path_annotation(a) for a in args if a is not None)
    if origin is not None:
        # Annotated[Path, ...] or similar
        args = get_args(annotation)
        return any(is_path_annotation(a) for a in args if a is not None)
    return False


def sandbox_paths(*param_names: str) -> Callable:
    """
    Decorator that sanitizes/normalizes path-like parameters
    before invoking the command function.
    """
    def outer(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            ba = sig.bind_partial(*args, **kwargs)
            ba.apply_defaults()

            def _sanitize(v: Any) -> Any:
                if isinstance(v, (str, Path, os.PathLike)):
                    return sanitize_path(v)
                if isinstance(v, (list, tuple, set)):
                    t = type(v)
                    return t(_sanitize(x) for x in v)
                return v

            for name in param_names:
                if name in ba.arguments and ba.arguments[name] is not None:
                    ba.arguments[name] = _sanitize(ba.arguments[name])

            return func(*ba.args, **ba.kwargs)
        return wrapper
    return outer
