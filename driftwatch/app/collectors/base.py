from __future__ import annotations

from dataclasses import dataclass, field

from driftwatch.app.core.config import AppConfig


@dataclass(slots=True)
class CollectorResult:
    name: str
    records: list[dict]
    metadata: dict = field(default_factory=dict)


class BaseCollector:
    name = "collector"
    supported_os = {"linux", "macos", "windows"}

    def collect(self, config: AppConfig, settings: dict[str, object]) -> CollectorResult:
        raise NotImplementedError
