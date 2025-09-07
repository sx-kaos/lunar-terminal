#!/usr/bin/env python3
# core/helpers/sysinfo.py
from __future__ import annotations

"""
System information utilities for Windows 11.

- Zero external dependencies.
- Uses PowerShell CIM when available and ctypes for memory/kernel stats.
- Python 3.10+; Windows 11 compatible.
"""

from dataclasses import asdict, dataclass
from typing import Any, Optional, Sequence
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess


# ----------------------------- utilities -----------------------------

def _powershell() -> Optional[str]:
    """Return PowerShell executable path if available, preferring 'pwsh'."""
    for exe in ("pwsh", "powershell"):
        path = shutil.which(exe)
        if path:
            return path
    return None


def _run_ps_json(script: str) -> Optional[Any]:
    """Run a PowerShell script and parse its JSON output; None on failure."""
    ps = _powershell()
    if not ps:
        return None

    cmd: list[str] = [
        ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", f"{script} | ConvertTo-Json -Depth 5 -Compress",
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except Exception:
        return None

    out = (proc.stdout or "").strip()
    if not out:
        return None

    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _bytes_to_gib(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sum_int(values: Sequence[Any]) -> Optional[int]:
    total = 0
    seen = False
    for v in values:
        try:
            total += int(v)  # type: ignore[arg-type]
            seen = True
        except (TypeError, ValueError):
            continue
    return total if seen else None


def _safe_percent(used: int, total: int) -> Optional[int]:
    try:
        if total <= 0:
            return None
        return int(round((used / total) * 100))
    except Exception:
        return None


# --------------------------- RAM (ctypes) ---------------------------

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        # Correct field name (typo fix): 'ull', not 'sull'
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _memory_status() -> Optional[MEMORYSTATUSEX]:
    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(  # type: ignore[attr-defined]
            ctypes.byref(stat)
        )
        return stat if ok else None
    except Exception:
        return None


# ------------------------------ models ------------------------------

@dataclass(slots=True)
class VolumeInfo:
    name: str = ""                     # e.g., "C:"
    label: Optional[str] = None        # e.g., "System"
    filesystem: Optional[str] = None   # e.g., "NTFS"
    total_gib: Optional[float] = None
    used_gib: Optional[float] = None
    free_gib: Optional[float] = None
    percent_used: Optional[int] = None
    drive_type: Optional[str] = None   # "Local Disk", "Removable", etc.
    removable: Optional[bool] = None


@dataclass(slots=True)
class DisksInfo:
    volumes: list[VolumeInfo]
    total_gib: Optional[float] = None
    used_gib: Optional[float] = None
    free_gib: Optional[float] = None
    percent_used: Optional[int] = None


@dataclass(slots=True)
class CPUInfo:
    name: str = ""
    physical_cores: Optional[int] = None
    logical_processors: Optional[int] = None
    max_clock_mhz: Optional[int] = None
    l2_cache_kb: Optional[int] = None
    l3_cache_kb: Optional[int] = None
    architecture: str = platform.machine()


@dataclass(slots=True)
class GPUInfo:
    name: str = ""
    driver_version: Optional[str] = None
    adapter_ram_gib: Optional[float] = None
    processor: Optional[str] = None


@dataclass(slots=True)
class RAMInfo:
    total_gib: Optional[float] = None
    available_gib: Optional[float] = None
    used_gib: Optional[float] = None
    percent_used: Optional[int] = None


@dataclass(slots=True)
class KernelInfo:
    name: str = ""
    version: Optional[str] = None
    build_number: Optional[int] = None


@dataclass(slots=True)
class SysInfo:
    cpu: CPUInfo
    gpus: list[GPUInfo]
    ram: RAMInfo
    kernel: KernelInfo
    os: str
    python: str
    disk: DisksInfo

    def ensure_full(self) -> None:
        """If GPU or Disk info is missing, gather it now."""
        if self.gpus is None or not self.gpus:
            self.gpus = get_gpu_info()
        if self.disk is None:
            self.disk = get_disks_info()


# ----------------------------- collectors -----------------------------

def get_cpu_info() -> CPUInfo:
    """Gather CPU info via CIM when possible; fallback to platform data."""
    data = _run_ps_json(
        "Get-CimInstance Win32_Processor | "
        "Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, "
        "MaxClockSpeed, L2CacheSize, L3CacheSize"
    )

    if isinstance(data, dict):
        items: Sequence[dict[str, Any]] = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    cpu = CPUInfo()
    if items:
        first = items[0]
        cpu.name = str(first.get("Name") or "").strip()
        cpu.max_clock_mhz = _safe_int(first.get("MaxClockSpeed"))
        cpu.l2_cache_kb = _safe_int(first.get("L2CacheSize"))
        cpu.l3_cache_kb = _safe_int(first.get("L3CacheSize"))
        cpu.physical_cores = _sum_int(x.get("NumberOfCores")
                                      for x in items)  # type: ignore[arg-type]
        cpu.logical_processors = _sum_int(
            x.get("NumberOfLogicalProcessors") for x in items # type: ignore[arg-type]
        )
    else:
        cpu.name = platform.processor() or platform.machine()

    cpu.name = re.sub(r" with .*$", "", cpu.name)
    return cpu


def get_gpu_info() -> list[GPUInfo]:
    """Collect GPU(s) via Win32_VideoController."""
    data = _run_ps_json(
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name, DriverVersion, AdapterRAM, VideoProcessor"
    )
    gpus: list[GPUInfo] = []
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for item in data:
            ram = _safe_int(item.get("AdapterRAM"))
            gpus.append(
                GPUInfo(
                    name=str(item.get("Name") or "").strip(),
                    driver_version=(
                        str(item.get("DriverVersion"))
                        if item.get("DriverVersion")
                        else None
                    ),
                    adapter_ram_gib=_bytes_to_gib(ram)
                    if isinstance(ram, int) and ram > 0
                    else None,
                    processor=(
                        str(item.get("VideoProcessor"))
                        if item.get("VideoProcessor")
                        else None
                    ),
                )
            )
    return gpus


def get_ram_info() -> RAMInfo:
    """Collect basic RAM stats using GlobalMemoryStatusEx."""
    stat = _memory_status()
    if not stat:
        return RAMInfo()
    total = int(stat.ullTotalPhys)
    avail = int(stat.ullAvailPhys)
    used = total - avail
    percent = int(stat.dwMemoryLoad)
    return RAMInfo(
        total_gib=_bytes_to_gib(total),
        available_gib=_bytes_to_gib(avail),
        used_gib=_bytes_to_gib(used),
        percent_used=percent,
    )


def get_kernel_info() -> KernelInfo:
    """Return Windows NT kernel name and version (major.minor.build)."""
    k = KernelInfo(name="Windows NT")

    # Primary: RtlGetVersion via ntdll (accurate kernel version)
    try:
        class RTL_OSVERSIONINFOW(ctypes.Structure):
            _fields_ = [
                ("dwOSVersionInfoSize", ctypes.c_ulong),
                ("dwMajorVersion", ctypes.c_ulong),
                ("dwMinorVersion", ctypes.c_ulong),
                ("dwBuildNumber", ctypes.c_ulong),
                ("dwPlatformId", ctypes.c_ulong),
                ("szCSDVersion", ctypes.c_wchar * 128),
            ]

        info = RTL_OSVERSIONINFOW()
        info.dwOSVersionInfoSize = ctypes.sizeof(RTL_OSVERSIONINFOW)
        ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined]
        status = ntdll.RtlGetVersion(ctypes.byref(info))
        if status == 0:
            k.build_number = int(info.dwBuildNumber)
            k.version = (
                f"{int(info.dwMajorVersion)}."
                f"{int(info.dwMinorVersion)}."
                f"{int(info.dwBuildNumber)}"
            )
            return k
    except Exception:
        pass

    # Fallback: CIM
    try:
        data = _run_ps_json(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Version, BuildNumber"
        )
        if isinstance(data, dict):
            k.version = (str(data.get("Version") or "").strip() or None)
            k.build_number = _safe_int(data.get("BuildNumber"))
            if k.version:
                return k
    except Exception:
        pass

    # Last resort: platform.version()
    try:
        ver = platform.version()
        k.version = ver or None
        m = re.search(r"\b(\d{5,})\b", ver)
        if m:
            k.build_number = int(m.group(1))
    except Exception:
        pass

    return k


def _drive_type_name_from_code(code: int) -> str:
    # WinAPI GetDriveType values
    return {
        0: "Unknown",
        1: "No Root Dir",
        2: "Removable",
        3: "Local Disk",
        4: "Network",
        5: "CD-ROM",
        6: "RAM Disk",
    }.get(int(code), "Unknown")


def _drive_type_name(path: str) -> Optional[str]:
    try:
        # type: ignore[attr-defined]
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.restype = ctypes.c_uint
        code = get_drive_type(ctypes.c_wchar_p(path))
        return _drive_type_name_from_code(code)
    except Exception:
        return None


def get_disks_info() -> DisksInfo:
    """Collect per-volume and aggregate disk usage (GiB) on Windows."""
    # Primary: PowerShell CIM
    data = _run_ps_json(
        "Get-CimInstance Win32_LogicalDisk | "
        "Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace, DriveType"
    )

    volumes: list[VolumeInfo] = []
    total_bytes = used_bytes = free_bytes = 0
    any_seen = False

    def _accumulate(size: int, free: int) -> None:
        nonlocal total_bytes, used_bytes, free_bytes, any_seen
        total_bytes += size
        free_bytes += free
        used_bytes += max(size - free, 0)
        any_seen = True

    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    if items:
        for it in items:
            try:
                device = str(it.get("DeviceID") or "").strip()  # "C:"
                size = _safe_int(it.get("Size")) or 0
                free = _safe_int(it.get("FreeSpace")) or 0
                used = max(size - free, 0)

                drive_type_code = _safe_int(it.get("DriveType"))
                drive_type = _drive_type_name_from_code(
                    drive_type_code if drive_type_code is not None else -1
                )

                if size <= 0:
                    continue

                vol = VolumeInfo(
                    name=device,
                    label=(str(it.get("VolumeName"))
                           if it.get("VolumeName") else None),
                    filesystem=(str(it.get("FileSystem"))
                                if it.get("FileSystem") else None),
                    total_gib=_bytes_to_gib(size),
                    used_gib=_bytes_to_gib(used),
                    free_gib=_bytes_to_gib(free),
                    percent_used=_safe_percent(used, size),
                    drive_type=drive_type,
                    removable=True if drive_type == "Removable"
                    else False if drive_type
                    else None,
                )
                volumes.append(vol)
                _accumulate(size, free)
            except Exception:
                continue

    # Fallback: stdlib scan of A:..Z:
    if not volumes:
        for letter in (chr(c) for c in range(ord("A"), ord("Z") + 1)):
            root = f"{letter}:\\"
            if not os.path.exists(root):
                continue
            try:
                usage = shutil.disk_usage(root)
            except Exception:
                continue

            size = int(usage.total)
            free = int(usage.free)
            used = max(size - free, 0)
            if size <= 0:
                continue

            dtype = _drive_type_name(root)

            volumes.append(
                VolumeInfo(
                    name=f"{letter}:",
                    label=None,
                    filesystem=None,
                    total_gib=_bytes_to_gib(size),
                    used_gib=_bytes_to_gib(used),
                    free_gib=_bytes_to_gib(free),
                    percent_used=_safe_percent(used, size),
                    drive_type=dtype,
                    removable=True if dtype == "Removable"
                    else False if dtype
                    else None,
                )
            )
            _accumulate(size, free)

    # Aggregate
    if any_seen:
        agg_total_gib = _bytes_to_gib(total_bytes)
        agg_free_gib = _bytes_to_gib(free_bytes)
        agg_used_gib = _bytes_to_gib(used_bytes)
        agg_percent = _safe_percent(used_bytes, total_bytes)
    else:
        agg_total_gib = agg_free_gib = agg_used_gib = None
        agg_percent = None

    return DisksInfo(
        volumes=volumes,
        total_gib=agg_total_gib,
        used_gib=agg_used_gib,
        free_gib=agg_free_gib,
        percent_used=agg_percent,
    )


def get_sysinfo(minimal: bool = False) -> SysInfo:
    """
    Collect system information.

    Args:
        minimal (bool): If True, only collect essentials (OS, CPU, RAM).
                        GPU and Disk are skipped until explicitly accessed.

    Returns:
        SysInfo: Structured system info.
    """
    # Always gather OS + CPU + RAM
    cpu = get_cpu_info()
    ram = get_ram_info()
    kernel = get_kernel_info()

    if minimal:
        return SysInfo(cpu=cpu, ram=ram, kernel=kernel, gpus=[], disk=None, os=None, python=None) # type: ignore[arg-type]

    # Full probe (slower)
    gpus = get_gpu_info()
    disk = get_disks_info()
    os_name = f"{platform.system()} {platform.release()}"
    python_ver = platform.python_version()
    return SysInfo(cpu=cpu, ram=ram, kernel=kernel, gpus=gpus, disk=disk, os=os_name, python=python_ver)


def to_json(info: SysInfo) -> str:
    """Serialize SysInfo to pretty JSON (stable field order)."""
    payload = asdict(info)
    return json.dumps(payload, indent=2)


# ------------------------------ CLI ------------------------------

def main() -> None:
    print(to_json(get_sysinfo()))


if __name__ == "__main__":
    main()
