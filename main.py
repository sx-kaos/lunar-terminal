from __future__ import annotations

"""
Application entrypoint (no CLI args).

Responsibilities:
- Run boot sequence (workspace, logger, commands, sysinfo).
- Start REPL with robust Ctrl+C / EOF handling.
"""

from pathlib import Path
import os
import platform
import random
import sys
import time

from core.boot import boot_sequence, BootState
from core.interface import _is_admin_user, handle_line, make_cli
from core.ui import clear_screen, colorize, print_line

BOOT_TIME = time.time()
VERSION = "4-dev"

TIPS = [
    "Use 'help system' to see Windows diagnostics commands.",
    "Press Ctrl+C to clear input line safely.",
    "Run 'whoami' to check your current privileges.",
    "Try 'dns-lookup <domain>' under recon to resolve hosts.",
    "Use tab completion to explore available commands quickly.",
]

LOGO = r"""
      ooooooooooooooooooooooooooooooooooooo
      8                                .d88    <user>@<host>
      8  oooooooooooooooooooooooooooood8888    -------------
      8  8888888888888888888888888P"   8888    OS: <os>
      8  8888888888888888888888P"      8888    Kernel: <kernel>
      8  88888888888888888888P"        8888    Packages: <plugins>
      8  8888888888888888P"            8888    CPU: <CPU>
      8  8888888888888P"               8888    GPU: <GPU>
      8  8888888888P"                  8888    Memory: <RAM>
      8  8888888P"                     8888    Disk: <DISK>
      8  8888P"                        8888    Boot time: <BOOT>
      8  8888oooooooooooooooooooooooomm8888    Workspace: <WORKSPACE>
      8 .od88888888888888888888888888888888    Commands loaded: <COMMANDS_LOADED>
      8888888888888888888888888888888888888    Version: <VERSION>

         ooooooooooooooooooooooooooooooo       TIP: <TIP>
        d                       ...oood8b
       d              ...oood888888888888b
      d     ...oood88888888888888888888888b
     dood8888888888888888888888888888888888b

     
"""


# ---------- presentation ----------

def _fmt_ram(used: float | None, total: float | None, pct: int | None) -> str:
    if used is None or total is None or pct is None:
        return "N/A"
    return f"{used}GiB / {total}GiB ({pct}%)"


def _fmt_disk(used: float | None, total: float | None, pct: int | None) -> str:
    if used is None or total is None or pct is None:
        return "N/A"
    return f"{used}GiB / {total}GiB ({pct}%)"


def generate_startup_text(*, state: BootState) -> str:
    """Build the colored ASCII dashboard using preloaded BootState."""
    user = "root" if _is_admin_user() else os.getlogin()
    host = platform.uname().node
    os_name = f"{platform.system()} {platform.release()}"
    tip = random.choice(TIPS)
    boot_ms = f"{(time.time() - BOOT_TIME) * 1000:.2f}ms"

    s = state.sysinfo
    cpu = f"{s.cpu.name} @ {((s.cpu.max_clock_mhz or 0) / 1000):.2f}GHz" if s.cpu.name else "N/A"
    gpu = (s.gpus[0].name if s.gpus and s.gpus[0].name else "N/A")
    ram = _fmt_ram(s.ram.used_gib, s.ram.total_gib, s.ram.percent_used)
    kernel = f"{s.kernel.name} {s.kernel.version} (Build {s.kernel.build_number})"
    disk = _fmt_disk(s.disk.used_gib, s.disk.total_gib, s.disk.percent_used)
    workspace = Path.cwd().resolve().name
    commands_loaded = state.loaded_count

    return (
        LOGO.replace("<user>", colorize(user, "cyan"))
        .replace("<host>", colorize(host, "cyan"))
        .replace("<os>", colorize(os_name, "cyan"))
        .replace("<kernel>", colorize(kernel, "cyan"))
        .replace("<plugins>", colorize(str(commands_loaded), "cyan"))
        .replace("<CPU>", colorize(cpu, "cyan"))
        .replace("<GPU>", colorize(gpu, "cyan"))
        .replace("<RAM>", colorize(ram, "cyan"))
        .replace("<DISK>", colorize(disk, "cyan"))
        .replace("<BOOT>", colorize(boot_ms, "cyan"))
        .replace("<WORKSPACE>", colorize(workspace, "cyan"))
        .replace("<COMMANDS_LOADED>", colorize(str(commands_loaded), "cyan"))
        .replace("<VERSION>", colorize(VERSION, "cyan"))
        .replace("<TIP>", colorize(tip, "cyan"))
    )


# ---------- REPL ----------

def run_repl(startup_text: str, logger) -> int:
    """Interactive loop with resilient Ctrl+C / EOF handling."""
    clear_screen()
    print_line(startup_text)

    cli = make_cli()
    try:
        cli.setup()
        while True:
            try:
                line = cli.get_line()
                result = handle_line(line)
                if result:
                    print_line(result)
            except (EOFError, KeyboardInterrupt):
                print_line("\nBye.")
                return 0
            except SystemExit:
                print_line("Bye.")
                return 0
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Unhandled error: {exc}")
    finally:
        try:
            cli.teardown()
        except Exception:
            pass
    return 0


# ---------- entrypoint ----------

def main() -> int:
    state = boot_sequence()
    startup = generate_startup_text(state=state)
    return run_repl(startup, state.logger)


if __name__ == "__main__":
    sys.exit(main())
