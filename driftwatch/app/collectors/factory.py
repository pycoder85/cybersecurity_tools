from __future__ import annotations

from driftwatch.app.collectors.base import BaseCollector
from driftwatch.app.collectors.common import HostCollector, NetworkCollector, ProcessCollector
from driftwatch.app.collectors.linux.collectors import LinuxFilesystemCollector, LinuxPersistenceCollector
from driftwatch.app.collectors.macos.collectors import MacOSFilesystemCollector, MacOSPersistenceCollector
from driftwatch.app.collectors.windows.collectors import WindowsFilesystemCollector, WindowsPersistenceCollector


def build_collectors(os_family: str) -> list[BaseCollector]:
    collectors: list[BaseCollector] = [HostCollector(), ProcessCollector(), NetworkCollector()]
    if os_family == "windows":
        collectors.extend([WindowsFilesystemCollector(), WindowsPersistenceCollector()])
    elif os_family == "macos":
        collectors.extend([MacOSFilesystemCollector(), MacOSPersistenceCollector()])
    else:
        collectors.extend([LinuxFilesystemCollector(), LinuxPersistenceCollector()])
    return collectors
