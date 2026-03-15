from __future__ import annotations

import platform


def detect_os_family() -> str:
    system_name = platform.system().lower()
    if system_name.startswith("darwin"):
        return "macos"
    if system_name.startswith("windows"):
        return "windows"
    return "linux"
