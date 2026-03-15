from __future__ import annotations

import threading
from time import monotonic

from driftwatch.app.core.config import AppConfig
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.scanner import run_scan
from driftwatch.app.services.settings import get_settings


class ScanScheduler:
    def __init__(self, config: AppConfig):
        self.config = config
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_run = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="driftwatch-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            with session_scope(self.config.database_url) as session:
                settings = get_settings(session)
            interval_minutes = int(settings.get("schedule_interval_minutes") or 0)
            if interval_minutes > 0:
                now = monotonic()
                if now - self._last_run >= interval_minutes * 60:
                    run_scan(self.config)
                    self._last_run = now
            self._stop.wait(15)
