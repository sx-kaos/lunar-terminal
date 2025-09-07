#!/usr/bin/env python3
# core/db/config.py
from __future__ import annotations

"""
Configuration loader (stdlib-only, Python 3.13).

Precedence (low → high):
  1) Built-in defaults
  2) Files in CWD: .env, config.ini, config.json, config.toml
  3) Environment variables

Validation:
  - PLUGIN_PATH: must be an existing directory
  - WORKSPACE_PATH: normalized path (no creation here)
  - LOG_FILE_PATH: None or normalized path
  - DISABLE_EFS / SHOW_BANNER / TIP_OF_DAY / ENABLE_COMPLETION: bool
  - PROMPT: None or str
  - LOG_LEVEL: None or one of {'DEBUG','INFO','WARNING','ERROR','CRITICAL'}
  - TIMEOUT: int >= 1
  - RETRIES: int >= 0
"""

from dataclasses import dataclass, field
from typing import Any, Mapping
from pathlib import Path
import configparser
import json
import os
import sys
import getpass
import re
import tomllib  # stdlib in 3.11+
from core.ui import print_line, colorize

# ---------- defaults ----------


def _default_workspace_path() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(
            Path.home() / "AppData" / "Local")
        return str(Path(base) / "Lunar")
    # POSIX
    return str(Path.home() / ".local" / "share" / "Lunar")


DEFAULTS: dict[str, Any] = {
    "PLUGIN_PATH": "plugins",
    "WORKSPACE_PATH": _default_workspace_path(),
    "LOG_FILE_PATH": None,
    # EFS enabled by default (so disable=False) - Windows only
    "DISABLE_EFS": False,
    "PROMPT": None,
    "LOG_LEVEL": None,              # 'DEBUG'/'INFO'/'WARNING'/'ERROR'/'CRITICAL'
    "SHOW_BANNER": True,
    "TIP_OF_DAY": True,
    "ENABLE_COMPLETION": True,
    "TIMEOUT": 5,
    "RETRIES": 2,
    "KEYSTORE_BACKEND": "aes-gcm",  # 'dpapi', 'aes-gcm', 'chachapoly1305'
    "KEYSTORE_PASSPHRASE": None,    # passphrase for portable backends
    # path to keyfile for portable backends (creates if missing at runtime)
    "KEYSTORE_KEYFILE": None,
    "AES_N": 2**14,                 # CPU/memory cost parameter for AES
    "AES_R": 8,                     # block size parameter for AES
    "AES_P": 1,                     # parallelization parameter for AES
}

# ---------- keystore helpers ----------


_ALLOWED_BACKENDS = {"dpapi", "aes-gcm", "chachapoly1305"}


def _validate_keystore_keys(config: dict[str, Any]) -> None:
    """
    Validate keystore-related settings without modifying them.
    Raises ValueError on invalid combinations.
    """
    backend = _as_opt_str(config.get("KEYSTORE_BACKEND"))
    if backend is not None and backend not in _ALLOWED_BACKENDS:
        raise ValueError(
            f"KEYSTORE_BACKEND must be one of {_ALLOWED_BACKENDS}, got {backend!r}")

    # If backend is portable, require either passphrase or keyfile.
    if backend in {"aes-gcm", "chachapoly1305"}:
        has_pw = _as_opt_str(config.get("KEYSTORE_PASSPHRASE")) is not None
        has_kf = _as_opt_str(config.get("KEYSTORE_KEYFILE")) is not None
        if not has_kf:
            raise ValueError("For portable backends, set KEYSTORE_KEYFILE")
        elif not has_pw:  # keyfile is set, passphrase is optional
            print_line(colorize(
                "[ WARN ] Warning: KEYSTORE_PASSPHRASE is not set; using keyfile only.", "yellow"))

        # Validate AES params (only needed when using passphrase)
        if has_pw:
            n = _as_int(config.get("AES_N", DEFAULTS["AES_N"]))
            r = _as_int(config.get("AES_R", DEFAULTS["AES_R"]))
            p = _as_int(config.get("AES_P", DEFAULTS["AES_P"]))
            if n <= 1 or r <= 0 or p <= 0:
                raise ValueError("AES_N/R/P must be positive; N>1")


def _write_config_file_toml(cfg_map: dict[str, Any], *, path: Path | None = None) -> Path:
    """
    Persist a TOML config near the CWD, with safe file perms where possible.
    Returns the path written.
    """
    out = (path or (Path.cwd() / "config.toml")).resolve()
    try:
        # Minimal TOML writer (no external deps)
        def _toml_scalar(v: Any) -> str:
            if isinstance(v, bool):
                return "true" if v else "false"
            if v is None:
                return '""'
            if isinstance(v, (int, float)):
                return str(v)
            s = str(v).replace("\\", "\\\\").replace('"', '\\"')
            return f'"{s}"'

        lines = []
        for k in sorted(cfg_map.keys()):
            lines.append(f'{k} = {_toml_scalar(cfg_map[k])}')
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Best-effort restrictive perms
        try:
            os.chmod(out, 0o600)
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Failed to write config at {out}: {exc}") from exc
    return out


def _resolve_under(base: Path, value: str | None, *, default_rel: str | None = None) -> Path | None:
    """Resolve a config path relative to `base` (workspace) when not absolute."""
    if value is None or str(value).strip() == "":
        if default_rel is None:
            return None
        return (base / default_rel).resolve()
    p = Path(os.path.expandvars(os.path.expanduser(str(value))))
    return p if p.is_absolute() else (base / p).resolve()


# ---------- data model ----------

@dataclass(frozen=True)
class AppConfig:
    plugin_path: Path
    workspace_path: Path
    log_file_path: Path | None

    disable_efs: bool
    prompt: str | None
    log_level: str | None
    show_banner: bool
    tip_of_day: bool
    enable_completion: bool

    timeout: int
    retries: int

    # Unrecognized keys preserved for debugging/forward-compat
    extra: dict[str, Any] = field(default_factory=dict)

# ---------- interactive creator ----------


def ensure_config_interactive(*, force: bool = False) -> AppConfig:
    """Interactive first-run config creator. Writes a simple, relative config.toml."""
    if not force:
        try:
            return load_config()
        except Exception:
            pass  # fall through

    print("Configuration setup (interactive)")
    print("--------------------------------")

    # --- use RELATIVE defaults; do NOT resolve here ---
    def ask_text(prompt: str, default: str) -> str:
        val = input(f"{prompt} [{default}]: ").strip()
        return val or default

    plugin_default = "plugins"
    workspace_default = "."
    log_default = "cst.log"

    plugin_path = ask_text(
        "Path to plugins (relative to workspace)", plugin_default)
    workspace_path = ask_text(
        "Path to workspace ('.' for current)", workspace_default)
    log_file_path = ask_text("Log file path (blank to disable)", log_default)

    print("\nKeystore backend (how workspace keys are protected):")
    print("  1) dpapi (Windows only, user-bound)")
    print("  2) aes-gcm (portable; (passphrase|keyfile) → AES-256-GCM)")
    print("  3) chachapoly1305 (portable; (passphrase|keyfile) → ChaCha20-Poly1305)")
    choice = (input("Choose [1/2/3]: ").strip() or "2")
    backend = {"1": "dpapi", "2": "aes-gcm",
               "3": "chachapoly1305"}.get(choice, "aes-gcm")

    keystore_pass = None
    keystore_keyfile = None
    aes_n, aes_r, aes_p = DEFAULTS["AES_N"], DEFAULTS["AES_R"], DEFAULTS["AES_P"]

    if backend in {"aes-gcm", "chachapoly1305"}:
        mode = (input(
            "Use passphrase or keyfile? [passphrase/keyfile] (default: keyfile): ").strip().lower() or "keyfile")
        if mode.startswith("pass"):
            pw1 = getpass.getpass("Enter keystore passphrase: ")
            pw2 = getpass.getpass("Confirm passphrase: ")
            if pw1 != pw2:
                print("Passphrases do not match.", file=sys.stderr)
                sys.exit(2)
            keystore_pass = pw1
            try:
                n_in = input(f"aes N (default {aes_n}): ").strip()
                r_in = input(f"aes r (default {aes_r}): ").strip()
                p_in = input(f"aes p (default {aes_p}): ").strip()
                if n_in:
                    aes_n = _as_int(n_in)
                if r_in:
                    aes_r = _as_int(r_in)
                if p_in:
                    aes_p = _as_int(p_in)
            except Exception as exc:  # noqa: BLE001
                print(f"Ignoring invalid aes settings: {exc}", file=sys.stderr)
        else:
            # keep relative by default (created at runtime if you want; not here)
            keystore_keyfile = input(
                "Keyfile path (relative; created if missing at runtime) [key.bin]: ").strip() or "key.bin"

    # Build a flat map WITHOUT resolving paths; loader will resolve under workspace.
    raw: dict[str, Any] = dict(DEFAULTS)
    raw.update({
        "PLUGIN_PATH": plugin_path,
        "WORKSPACE_PATH": workspace_path,
        "LOG_FILE_PATH": "" if (log_file_path.strip() == "") else log_file_path,
        "KEYSTORE_BACKEND": backend,
        "KEYSTORE_PASSPHRASE": keystore_pass or "",
        "KEYSTORE_KEYFILE": keystore_keyfile or "",
        "AES_N": aes_n,
        "AES_R": aes_r,
        "AES_P": aes_p,
    })

    # Validate keystore keys (normalizes backend)
    _validate_keystore_keys(raw)
    # Validate general fields (does not create files/dirs)
    _validate_and_build(raw)

    # Persist RELATIVE config
    path = _write_config_file_toml(raw)
    print(f"\nSaved configuration → {path}")

    # Reload through the normal path
    return _validate_and_build(_merge_sources())


# ---------- file loaders (stdlib) ----------

def _load_env_file(path: Path) -> dict[str, str]:
    """Very small .env parser: KEY=VALUE, supports quotes; ignores comments/blank lines."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out

    line_re = re.compile(r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$""")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
            v = v[1:-1]
        out[k] = v
    return out


def _load_ini_file(path: Path) -> dict[str, str]:
    cfg = configparser.ConfigParser()
    try:
        cfg.read(path, encoding="utf-8")
    except FileNotFoundError:
        return {}
    flat: dict[str, str] = {}
    for sec in cfg.sections():
        for k, v in cfg.items(sec):
            flat[k.upper()] = v
    return flat


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_toml_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        return {}


def _flatten_mapping(obj: Any, prefix: str = "") -> dict[str, Any]:
    """
    Flatten nested dicts to UPPER_SNAKE keys.
    Example: {'ui': {'show_banner': true}} -> {'UI_SHOW_BANNER': True}
    We accept both flat and nested styles; flat keys win on collisions later.
    """
    flat: dict[str, Any] = {}
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            key = f"{prefix}_{k}" if prefix else str(k)
            if isinstance(v, Mapping):
                flat.update(_flatten_mapping(v, key))
            else:
                flat[str(key).upper()] = v
    return flat


def _find_config_files() -> list[Path]:
    cwd = Path.cwd()
    return [
        cwd / ".env",
        cwd / "config.ini",
        cwd / "config.json",
        cwd / "config.toml",
    ]


# ---------- normalization & coercion ----------

_BOOL_TRUE = {"1", "true", "yes", "y", "on"}
_BOOL_FALSE = {"0", "false", "no", "n", "off"}


def _as_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in _BOOL_TRUE:
        return True
    if s in _BOOL_FALSE:
        return False
    raise ValueError(f"Expected boolean, got: {val!r}")


def _as_int(val: Any) -> int:
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    try:
        return int(str(val).strip())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Expected integer, got: {val!r}") from exc


def _as_opt_str(val: Any) -> str | None:
    return None if val is None or str(val).strip().lower() in {"", "none"} else str(val)


def _as_log_level(val: Any) -> str | None:
    lv = _as_opt_str(val)
    if lv is None:
        return None
    up = lv.upper()
    allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if up not in allowed:
        raise ValueError(
            f"LOG_LEVEL must be one of {sorted(allowed)}, got {lv!r}")
    return up


def _as_path(val: Any) -> Path:
    s = str(val)
    # expand both ~ and env vars
    s = os.path.expandvars(os.path.expanduser(s))
    return Path(s).resolve()


def _as_opt_path(val: Any) -> Path | None:
    v = _as_opt_str(val)
    return None if v is None else _as_path(v)


# ---------- merge & load ----------

def _merge_sources() -> dict[str, Any]:
    merged: dict[str, Any] = dict(DEFAULTS)

    for file in _find_config_files():
        if file.suffix == ".env":
            merged.update(_normalize_keys(_load_env_file(file)))
        elif file.suffix == ".ini":
            merged.update(_normalize_keys(_load_ini_file(file)))
        elif file.suffix == ".json":
            merged.update(_normalize_keys(
                _flatten_mapping(_load_json_file(file))))
        elif file.suffix == ".toml":
            merged.update(_normalize_keys(
                _flatten_mapping(_load_toml_file(file))))

    # Environment variables override all; only take UPPERCASE-like keys
    env_overrides = {k: v for k, v in os.environ.items()
                     if re.fullmatch(r"[A-Z0-9_]+", k)}
    merged.update(env_overrides)
    return merged


def _normalize_keys(d: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k).upper(): v for k, v in d.items()}


# ---------- validation ----------

def _validate_and_build(config: dict[str, Any]) -> AppConfig:
    # --- gather raw strings first (no resolution yet) ---
    plugin_raw = config.get("PLUGIN_PATH", DEFAULTS["PLUGIN_PATH"])
    workspace_raw = config.get("WORKSPACE_PATH", DEFAULTS["WORKSPACE_PATH"])
    log_raw = config.get("LOG_FILE_PATH", DEFAULTS["LOG_FILE_PATH"])

    # workspace base: if relative, it's relative to CWD (first run); then used as base
    ws_base = Path(os.path.expandvars(os.path.expanduser(str(workspace_raw))))
    if not ws_base.is_absolute():
        ws_base = (Path.cwd() / ws_base).resolve()
    workspace_path = ws_base.resolve()

    # resolve the others INSIDE the workspace
    plugin_path = _resolve_under(
        workspace_path, plugin_raw, default_rel="plugins")
    log_file_path = _resolve_under(
        workspace_path, log_raw, default_rel="cst.log")

    # --- basic coercions ---
    disable_efs = _as_bool(config.get("DISABLE_EFS", DEFAULTS["DISABLE_EFS"]))
    prompt = _as_opt_str(config.get("PROMPT", DEFAULTS["PROMPT"]))
    log_level = _as_log_level(config.get("LOG_LEVEL", DEFAULTS["LOG_LEVEL"]))
    show_banner = _as_bool(config.get("SHOW_BANNER", DEFAULTS["SHOW_BANNER"]))
    tip_of_day = _as_bool(config.get("TIP_OF_DAY", DEFAULTS["TIP_OF_DAY"]))
    enable_completion = _as_bool(config.get(
        "ENABLE_COMPLETION", DEFAULTS["ENABLE_COMPLETION"]))
    timeout = _as_int(config.get("TIMEOUT", DEFAULTS["TIMEOUT"]))
    retries = _as_int(config.get("RETRIES", DEFAULTS["RETRIES"]))

    # --- constraints (no filesystem creation here) ---
    # Do NOT require plugin_path to exist on first run; just ensure it's a path.
    if timeout < 1:
        raise ValueError("TIMEOUT must be >= 1")
    if retries < 0:
        raise ValueError("RETRIES must be >= 0")

    # --- keystore validation & normalization for visibility ---
    ks_backend = _as_opt_str(config.get("KEYSTORE_BACKEND"))
    tmp = dict(config)
    if ks_backend is not None:
        tmp["KEYSTORE_BACKEND"] = ks_backend
    _validate_keystore_keys(tmp)

    # Carry through extra keys (post-normalization)
    recognized = set(DEFAULTS.keys())
    extra = {k: (tmp[k] if k in tmp else v)
             for k, v in config.items() if k not in recognized}
    if ks_backend is not None:
        extra["KEYSTORE_BACKEND"] = ks_backend  # keep normalized in extra

    return AppConfig(
        plugin_path=plugin_path,  # type: ignore[arg-type]
        workspace_path=workspace_path,
        log_file_path=log_file_path,
        disable_efs=disable_efs,
        prompt=prompt,
        log_level=log_level,
        show_banner=show_banner,
        tip_of_day=tip_of_day,
        enable_completion=enable_completion,
        timeout=timeout,
        retries=retries,
        extra=extra,
    )


def keystore_env_from_config() -> dict[str, str]:
    """Return normalized keystore env vars from merged config sources.

    - If backend is portable and both KEYSTORE_PASSPHRASE / KEYSTORE_KEYFILE are empty,
      chooses a sensible default keyfile name: "key.bin".
    - Returns only string values (ready to put in os.environ).
    """
    raw = _merge_sources()

    backend = _as_opt_str(raw.get("KEYSTORE_BACKEND")) or ""
    passphrase = _as_opt_str(raw.get("KEYSTORE_PASSPHRASE")) or ""
    keyfile = _as_opt_str(raw.get("KEYSTORE_KEYFILE")) or ""
    n = str(_as_int(raw.get("AES_N", DEFAULTS["AES_N"])))
    r = str(_as_int(raw.get("AES_R", DEFAULTS["AES_R"])))
    p = str(_as_int(raw.get("AES_P", DEFAULTS["AES_P"])))

    # If portable and both are empty, default to a keyfile name (to be resolved at boot)
    if backend in {"aes-gcm", "chachapoly1305"} and not passphrase and not keyfile:
        keyfile = "key.bin"

    out: dict[str, str] = {}
    if backend:
        out["KEYSTORE_BACKEND"] = backend
    if passphrase:
        out["KEYSTORE_PASSPHRASE"] = passphrase
    if keyfile:
        out["KEYSTORE_KEYFILE"] = keyfile
    out["AES_N"] = n
    out["AES_R"] = r
    out["AES_P"] = p
    return out


# ---------- public API ----------

def load_config() -> AppConfig:
    """
    Load, merge, normalize, and validate configuration.
    No filesystem side-effects (no directory creation).
    """
    raw = _merge_sources()
    return _validate_and_build(raw)


def validate_or_create_config() -> AppConfig:
    try:
        return load_config()
    except Exception as exc:  # noqa: BLE001
        if 'set KEYSTORE_KEYFILE' in str(exc):
            return ensure_config_interactive(force=True)
        print_line(
            colorize(f"[ WARN ] Invalid configuration: {exc}", "yellow"))
        return ensure_config_interactive(force=True)
