from __future__ import annotations

import csv
import os
import re
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


WINDOWS_EXECUTABLE_SUFFIXES = (".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi")
SERVICE_START_TYPES = {
    0: "boot",
    1: "system",
    2: "auto",
    3: "manual",
    4: "disabled",
}


def _parse_windows_command_path(command: str) -> str:
    command = (command or "").strip()
    if not command:
        return ""
    if command.startswith('"'):
        parts = command.split('"')
        return parts[1].strip() if len(parts) > 1 else command.strip('"')
    matches = re.findall(r"[A-Za-z]:\\[^\"']+?\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|msi)", command, flags=re.IGNORECASE)
    if matches:
        return matches[0].strip()
    return command.split()[0] if " " in command else command


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
            author = row.get("Author") or ""
            run_as_user = row.get("Run As User") or ""
            status = row.get("Status") or row.get("Scheduled Task State") or ""
            schedule_type = row.get("Schedule Type") or row.get("Schedule") or ""
            image_path = _parse_windows_command_path(task_to_run)
            entries.append(
                {
                    "name": task_name,
                    "category": "scheduled_task",
                    "path": task_name,
                    "command": task_to_run,
                    "image_path": image_path,
                    "author": author,
                    "run_as_user": run_as_user,
                    "status": status,
                    "schedule_type": schedule_type,
                    "last_run_time": row.get("Last Run Time") or "",
                    "next_run_time": row.get("Next Run Time") or "",
                    "source": "windows.persistence",
                    "hash": stable_hash([task_name, task_to_run, author, run_as_user, status, schedule_type]),
                }
            )
        return entries

    def _services(self) -> list[dict]:
        states = self._service_states()
        if winreg is not None:
            return self._services_from_registry(states)
        return self._services_from_query(states)

    def _service_states(self) -> dict[str, str]:
        try:
            output = subprocess.check_output(
                ["sc", "query", "type=", "service", "state=", "all"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        states: dict[str, str] = {}
        current_name = ""
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("SERVICE_NAME:"):
                current_name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("STATE") and current_name:
                _, _, value = stripped.partition(":")
                state_value = value.strip().split()
                states[current_name] = state_value[1].lower() if len(state_value) > 1 else value.strip().lower()
        return states

    def _services_from_registry(self, states: dict[str, str]) -> list[dict]:
        if winreg is None:
            return []
        entries: list[dict] = []
        root_path = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path) as services_key:
                index = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(services_key, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(services_key, service_name) as service_key:
                            image_path = self._query_registry_value(service_key, "ImagePath")
                            display_name = self._query_registry_value(service_key, "DisplayName") or service_name
                            start_type_value = self._query_registry_value(service_key, "Start")
                            service_type_value = self._query_registry_value(service_key, "Type")
                            service_account = self._query_registry_value(service_key, "ObjectName")
                    except OSError:
                        continue
                    command = str(image_path or "")
                    parsed_path = _parse_windows_command_path(command)
                    entries.append(
                        {
                            "name": display_name,
                            "service_name": service_name,
                            "category": "service",
                            "path": parsed_path or service_name,
                            "command": command,
                            "image_path": parsed_path,
                            "start_mode": SERVICE_START_TYPES.get(start_type_value, str(start_type_value or "")),
                            "state": states.get(service_name, "unknown"),
                            "service_type": str(service_type_value or ""),
                            "service_account": str(service_account or ""),
                            "source": "windows.persistence",
                            "hash": stable_hash([service_name, command, start_type_value, states.get(service_name)]),
                        }
                    )
        except OSError:
            return self._services_from_query(states)
        return entries

    def _services_from_query(self, states: dict[str, str]) -> list[dict]:
        entries: list[dict] = []
        for service_name, state in states.items():
            entries.append(
                {
                    "name": service_name,
                    "service_name": service_name,
                    "category": "service",
                    "path": service_name,
                    "command": "",
                    "image_path": "",
                    "start_mode": "",
                    "state": state,
                    "service_type": "",
                    "service_account": "",
                    "source": "windows.persistence",
                    "hash": stable_hash([service_name, state]),
                }
            )
        return entries

    def _query_registry_value(self, key_handle, value_name: str):
        if winreg is None:
            return None
        try:
            value, _ = winreg.QueryValueEx(key_handle, value_name)
            return value
        except OSError:
            return None


class WindowsSoftwareCollector(BaseCollector):
    name = "software"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        records = self._installed_software()
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})

    def _installed_software(self) -> list[dict]:
        if winreg is None:
            return []
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        current_user = getattr(winreg, "HKEY_CURRENT_USER", None)
        if current_user is not None:
            roots.append((current_user, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"))

        records: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for hive, path in roots:
            try:
                with winreg.OpenKey(hive, path) as uninstall_key:
                    index = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(uninstall_key, index)
                        except OSError:
                            break
                        index += 1
                        try:
                            with winreg.OpenKey(uninstall_key, subkey_name) as package_key:
                                name = str(self._query_registry_value(package_key, "DisplayName") or "").strip()
                                version = str(self._query_registry_value(package_key, "DisplayVersion") or "").strip()
                                publisher = str(self._query_registry_value(package_key, "Publisher") or "").strip()
                                install_location = str(self._query_registry_value(package_key, "InstallLocation") or "").strip()
                                uninstall_string = str(self._query_registry_value(package_key, "UninstallString") or "").strip()
                                install_date = str(self._query_registry_value(package_key, "InstallDate") or "").strip()
                                estimated_size = self._query_registry_value(package_key, "EstimatedSize")
                        except OSError:
                            continue
                        if not name:
                            continue
                        dedupe_key = (name.lower(), version, publisher.lower())
                        if dedupe_key in seen:
                            continue
                        seen.add(dedupe_key)
                        records.append(
                            {
                                "name": name,
                                "version": version,
                                "publisher": publisher,
                                "architecture": "x86" if "WOW6432Node" in path else "",
                                "install_location": install_location,
                                "uninstall_command": uninstall_string,
                                "install_date": install_date,
                                "estimated_size_kb": int(estimated_size or 0) if str(estimated_size or "").isdigit() else estimated_size or 0,
                                "package_manager": "windows_uninstall_registry",
                                "source": "windows.software",
                                "hash": stable_hash([name, version, publisher, install_location]),
                            }
                        )
            except OSError:
                continue
        return records

    def _query_registry_value(self, key_handle, value_name: str):
        if winreg is None:
            return None
        try:
            value, _ = winreg.QueryValueEx(key_handle, value_name)
            return value
        except OSError:
            return None
