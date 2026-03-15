from __future__ import annotations

import subprocess
from pathlib import Path

from driftwatch.app.collectors.base import BaseCollector, CollectorResult
from driftwatch.app.collectors.common import GenericFilesystemCollector
from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.utils import stable_hash


class MacOSFilesystemCollector(GenericFilesystemCollector):
    temp_paths = ["/tmp", str(Path.home() / "Library" / "Caches"), str(Path.home() / "Library" / "Containers")]
    startup_paths = [
        str(Path.home() / "Library" / "LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        str(Path.home() / ".zshrc"),
        str(Path.home() / ".bash_profile"),
    ]
    authorized_key_paths = [str(Path.home() / ".ssh" / "authorized_keys")]
    sensitive_paths = [str(Path.home() / "Library" / "Preferences"), str(Path.home() / "Library" / "LaunchAgents")]


class MacOSPersistenceCollector(BaseCollector):
    name = "persistence"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        records: list[dict] = []
        candidate_paths = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        for candidate in candidate_paths:
            if not candidate.exists():
                continue
            for child in candidate.glob("*.plist"):
                records.append(
                    {
                        "name": child.name,
                        "category": "launchd",
                        "path": str(child),
                        "command": "",
                        "source": "macos.persistence",
                        "hash": stable_hash(str(child)),
                    }
                )
        login_items = self._collect_login_items()
        records.extend(login_items)
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})

    def _collect_login_items(self) -> list[dict]:
        try:
            output = subprocess.check_output(
                ["osascript", "-e", 'tell application "System Events" to get the name of every login item'],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).strip()
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        if not output:
            return []
        names = [item.strip() for item in output.split(",") if item.strip()]
        return [
            {
                "name": name,
                "category": "login_item",
                "path": "",
                "command": name,
                "source": "macos.persistence",
                "hash": stable_hash(name),
            }
            for name in names
        ]
