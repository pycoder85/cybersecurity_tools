from __future__ import annotations

import os
import platform
import socket
from pathlib import Path

import psutil

from driftwatch.app.collectors.base import BaseCollector, CollectorResult
from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.platform import detect_os_family
from driftwatch.app.core.utils import stable_hash, utcnow_iso


class HostCollector(BaseCollector):
    name = "host"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        record = {
            "hostname": socket.gethostname(),
            "os_family": detect_os_family(),
            "os_version": platform.platform(),
            "architecture": platform.machine(),
            "collected_at": utcnow_iso(),
            "boot_time": psutil.boot_time(),
            "cpu_count": psutil.cpu_count(logical=True),
            "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        }
        return CollectorResult(name=self.name, records=[record])


class ProcessCollector(BaseCollector):
    name = "processes"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        records: list[dict] = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "username", "exe", "cmdline", "cwd", "create_time", "status"]
        ):
            try:
                info = proc.info
                records.append(
                    {
                        "pid": info.get("pid"),
                        "ppid": info.get("ppid"),
                        "name": info.get("name") or "",
                        "username": info.get("username") or "",
                        "exe": info.get("exe") or "",
                        "cmdline": info.get("cmdline") or [],
                        "cwd": info.get("cwd") or "",
                        "status": info.get("status") or "",
                        "create_time": info.get("create_time"),
                    }
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})


class NetworkCollector(BaseCollector):
    name = "network"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        process_names: dict[int, str] = {}
        records: list[dict] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.Error):
            connections = []
        for connection in connections:
            pid = connection.pid or 0
            if pid and pid not in process_names:
                try:
                    process_names[pid] = psutil.Process(pid).name()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error):
                    process_names[pid] = ""
            records.append(
                {
                    "pid": pid,
                    "process_name": process_names.get(pid, ""),
                    "laddr": f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else "",
                    "lport": connection.laddr.port if connection.laddr else None,
                    "raddr": f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else "",
                    "rport": connection.raddr.port if connection.raddr else None,
                    "status": connection.status,
                    "family": str(connection.family),
                }
            )
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})


def _walk_limited(paths: list[str], max_depth: int = 3, max_files: int = 200) -> list[Path]:
    collected: list[Path] = []
    for base_path in paths:
        root = Path(base_path).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            collected.append(root)
            continue
        for current_root, dir_names, file_names in os.walk(root):
            rel_parts = Path(current_root).relative_to(root).parts if current_root != str(root) else ()
            if len(rel_parts) >= max_depth:
                dir_names[:] = []
            for file_name in file_names:
                collected.append(Path(current_root) / file_name)
                if len(collected) >= max_files:
                    return collected
    return collected


def _safe_stat(path: Path) -> dict:
    stat = path.stat()
    return {
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "mode": oct(stat.st_mode),
        "hash": stable_hash([str(path), stat.st_mtime, stat.st_size]),
    }


class GenericFilesystemCollector(BaseCollector):
    name = "filesystem"
    temp_paths: list[str] = []
    startup_paths: list[str] = []
    authorized_key_paths: list[str] = []
    sensitive_paths: list[str] = []

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        scan_directories = [str(item) for item in settings.get("scan_directories", [])]
        exclusions = {str(item) for item in settings.get("scan_exclusions", [])}
        records: list[dict] = []
        temp_candidates = _walk_limited(self.temp_paths, max_depth=2, max_files=120)
        startup_candidates = _walk_limited(self.startup_paths, max_depth=2, max_files=120)
        sensitive_candidates = _walk_limited(scan_directories + self.sensitive_paths, max_depth=2, max_files=120)
        for path in temp_candidates + startup_candidates + sensitive_candidates:
            if any(str(path).startswith(excluded) for excluded in exclusions):
                continue
            try:
                if not path.exists():
                    continue
                if path.is_dir():
                    continue
                stat_data = _safe_stat(path)
                suffix = path.suffix.lower()
                is_hidden = path.name.startswith(".")
                is_executable = os.access(path, os.X_OK) or suffix in {
                    ".exe",
                    ".dll",
                    ".ps1",
                    ".sh",
                    ".py",
                    ".pl",
                    ".bat",
                    ".cmd",
                    ".bin",
                    ".out",
                    ".run",
                }
                category = "recent_sensitive_file"
                if str(path).startswith(tuple(self.temp_paths)):
                    category = "temp_executable" if is_executable else "temp_file"
                elif str(path).startswith(tuple(self.startup_paths)):
                    category = "startup_file"
                record = {
                    "path": str(path),
                    "category": category,
                    "hidden": is_hidden,
                    "executable": is_executable,
                    **stat_data,
                }
                if is_hidden and (
                    str(path).startswith(tuple(self.temp_paths))
                    or str(path).startswith(tuple(self.startup_paths))
                ):
                    hidden_record = dict(record)
                    hidden_record["category"] = "hidden_file"
                    records.append(hidden_record)
                if category == "temp_executable" or category == "startup_file":
                    records.append(record)
                elif category == "recent_sensitive_file":
                    records.append(record)
            except (OSError, PermissionError):
                continue
        for key_path in self.authorized_key_paths:
            expanded = Path(key_path).expanduser()
            try:
                if not expanded.exists():
                    continue
                records.append({"path": str(expanded), "category": "authorized_keys", **_safe_stat(expanded)})
            except (OSError, PermissionError):
                continue
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})
