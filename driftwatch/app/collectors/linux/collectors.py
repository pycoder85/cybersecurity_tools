from __future__ import annotations

from pathlib import Path

from driftwatch.app.collectors.base import BaseCollector, CollectorResult
from driftwatch.app.collectors.common import GenericFilesystemCollector
from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.utils import stable_hash


class LinuxFilesystemCollector(GenericFilesystemCollector):
    temp_paths = ["/tmp", "/dev/shm", "/var/tmp"]
    startup_paths = ["/etc/profile.d", "/etc/systemd/system", str(Path.home() / ".config" / "autostart")]
    authorized_key_paths = [str(Path.home() / ".ssh" / "authorized_keys"), "/root/.ssh/authorized_keys"]
    sensitive_paths = ["/var/www", "/etc/cron.d", "/var/spool/cron"]


class LinuxPersistenceCollector(BaseCollector):
    name = "persistence"

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        records: list[dict] = []
        cron_paths = [Path("/etc/crontab"), Path("/etc/cron.d"), Path("/var/spool/cron")]
        systemd_paths = [Path("/etc/systemd/system"), Path("/usr/lib/systemd/system")]
        for cron_path in cron_paths:
            if cron_path.is_file():
                records.append(
                    {
                        "name": cron_path.name,
                        "category": "cron",
                        "path": str(cron_path),
                        "command": "",
                        "source": "linux.persistence",
                        "hash": stable_hash(str(cron_path)),
                    }
                )
            elif cron_path.is_dir():
                for child in cron_path.glob("*"):
                    if child.is_file():
                        records.append(
                            {
                                "name": child.name,
                                "category": "cron",
                                "path": str(child),
                                "command": "",
                                "source": "linux.persistence",
                                "hash": stable_hash(str(child)),
                            }
                        )
        for systemd_path in systemd_paths:
            if not systemd_path.exists():
                continue
            for child in systemd_path.glob("*.service"):
                records.append(
                    {
                        "name": child.name,
                        "category": "systemd_service",
                        "path": str(child),
                        "command": "",
                        "source": "linux.persistence",
                        "hash": stable_hash(str(child)),
                    }
                )
            for child in systemd_path.glob("*.timer"):
                records.append(
                    {
                        "name": child.name,
                        "category": "systemd_timer",
                        "path": str(child),
                        "command": "",
                        "source": "linux.persistence",
                        "hash": stable_hash(str(child)),
                    }
                )
        return CollectorResult(name=self.name, records=records, metadata={"count": len(records)})
