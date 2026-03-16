from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from driftwatch.app.core.platform import detect_os_family
from driftwatch.app.core.utils import ensure_directory


DEFAULT_TITLE = "Driftwatch"
DEFAULT_PORT = 8484


def default_data_dir() -> Path:
    custom_home = os.environ.get("DRIFTWATCH_HOME") or os.environ.get("SENTINELDESK_HOME")
    if custom_home:
        return ensure_directory(Path(custom_home).expanduser())
    return ensure_directory(Path.home() / ".driftwatch")


def default_scan_directories(os_family: str) -> list[str]:
    if os_family == "windows":
        return [
            os.environ.get("USERPROFILE", r"C:\Users\Public"),
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
        ]
    if os_family == "macos":
        return ["/tmp", str(Path.home() / "Library" / "LaunchAgents"), "/Library/LaunchDaemons"]
    return ["/tmp", "/var/www", "/etc/systemd/system"]


def default_exclusions(os_family: str) -> list[str]:
    if os_family == "windows":
        return [r"C:\Windows\SoftwareDistribution"]
    if os_family == "macos":
        return [str(Path.home() / "Library" / "Caches")]
    return ["/proc", "/sys", "/snap"]


@dataclass(slots=True)
class AppConfig:
    data_dir: Path
    database_url: str
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = DEFAULT_PORT
    dashboard_title: str = DEFAULT_TITLE

    @classmethod
    def from_env(cls) -> "AppConfig":
        data_dir = default_data_dir()
        database_path = data_dir / "driftwatch.db"
        return cls(
            data_dir=data_dir,
            database_url=f"sqlite:///{database_path}",
            dashboard_host=os.environ.get("DRIFTWATCH_HOST") or os.environ.get("SENTINELDESK_HOST", "127.0.0.1"),
            dashboard_port=int(os.environ.get("DRIFTWATCH_PORT") or os.environ.get("SENTINELDESK_PORT", DEFAULT_PORT)),
        )


def default_settings() -> dict[str, object]:
    os_family = detect_os_family()
    return {
        "scan_directories": default_scan_directories(os_family),
        "scan_exclusions": default_exclusions(os_family),
        "schedule_interval_minutes": 0,
        "llm_provider": "none",
        "llm_model": "",
        "enrichment_provider": "none",
        "enrichment_api_key": "",
        "response_actions_enabled": False,
        "web_roots": ["/var/www"] if os_family == "linux" else [],
    }
