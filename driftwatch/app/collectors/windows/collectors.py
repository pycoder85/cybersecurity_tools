from __future__ import annotations

import csv
import os
import subprocess
from io import StringIO
from pathlib import Path

from driftwatch.app.collectors.base import BaseCollector, CollectorResult
from driftwatch.app.collectors.common import GenericFilesystemCollector
from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.utils import stable_hash

try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover
    winreg = None


class WindowsFilesystemCollector(GenericFilesystemCollector):
    temp_paths = [os.environ.get("TEMP", r"C:\Windows\Temp"), os.environ.get("TMP", r"C:\Windows\Temp")]
    startup_paths = [
        os.path.join(
            os.environ.get("APPDATA", r"C:\Users\Public\AppData\Roaming"),
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            "Startup",
        ),
        os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
    authorized_key_paths = [os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Public"), ".ssh", "authorized_keys")]
    sensitive_paths = [
        os.path.join(os.environ.get("APPDATA", r"C:\Users\Public\AppData\Roaming"), "Microsoft", "Windows", "Start Menu"),
        os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu"),
    ]


class WindowsPersistenceCollector(BaseCollector):
    name = "persistence"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        records = []
        records.extend(self._registry_run_keys())
        records.extend(self._scheduled_tasks())
        records.extend(self._services())
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})

    def _registry_run_keys(self) -> list[dict]:
        if winreg is None:
            return []
        roots = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "registry_run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry_run_once"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "registry_run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry_run_once"),
        ]
        entries: list[dict] = []
        for hive, path, category in roots:
            try:
                with winreg.OpenKey(hive, path) as key_handle:
                    index = 0
                    while True:
                        name, value, _ = winreg.EnumValue(key_handle, index)
                        entries.append(
                            {
                                "name": name,
                                "category": category,
                                "path": path,
                                "command": str(value),
                                "source": "windows.persistence",
                                "hash": stable_hash([path, name, value]),
                            }
                        )
                        index += 1
            except OSError:
                continue
        return entries

    def _scheduled_tasks(self) -> list[dict]:
        try:
            output = subprocess.check_output(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        reader = csv.DictReader(StringIO(output))
        entries = []
        for row in reader:
            task_name = row.get("TaskName") or ""
            task_to_run = row.get("Task To Run") or row.get("Actions") or ""
            entries.append(
                {
                    "name": task_name,
                    "category": "scheduled_task",
                    "path": task_name,
                    "command": task_to_run,
                    "source": "windows.persistence",
                    "hash": stable_hash([task_name, task_to_run]),
                }
            )
        return entries

    def _services(self) -> list[dict]:
        try:
            output = subprocess.check_output(
                ["sc", "query", "type=", "service", "state=", "all"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        entries: list[dict] = []
        current_name = ""
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("SERVICE_NAME:"):
                current_name = stripped.split(":", 1)[1].strip()
                entries.append(
                    {
                        "name": current_name,
                        "category": "service",
                        "path": current_name,
                        "command": "",
                        "source": "windows.persistence",
                        "hash": stable_hash(current_name),
                    }
                )
        return entries
