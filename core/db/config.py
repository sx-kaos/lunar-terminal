#!/usr/bin/env python3
# core/db/config.py
from __future__ import annotations

"""
Simple configuration loader with environment overrides.

This avoids heavy dependencies; it is sufficient for CLI tooling.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    """
    Runtime configuration.

    Attributes:
        commands_package: Python package name to load commands from.
        workspace_override: Optional override for the secure workspace path.
        log_file_path: Optional path to a rotating log file (within workspace).
    """
    commands_package: str = os.environ.get(
        "CYBERSEC_COMMANDS_PKG", "plugins")
    workspace_override: str | None = os.environ.get(
        "CYBERSEC_WORKSPACE", None)
    log_file_path: str | None = os.environ.get(
        "CYBERSEC_LOG_FILE", None)
    disable_efs: bool = os.environ.get(
        "CST_DISABLE_EFS") in ("1", "true", "True", "TRUE")


def load_config() -> AppConfig:
    """Load configuration from environment variables."""
    return AppConfig()
