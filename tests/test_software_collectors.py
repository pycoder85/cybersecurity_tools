import importlib
import json
import sys
from types import SimpleNamespace


sys.modules.setdefault(
    "psutil",
    SimpleNamespace(
        boot_time=lambda: 0,
        cpu_count=lambda logical=True: 1,
        process_iter=lambda *args, **kwargs: [],
        net_connections=lambda *args, **kwargs: [],
        AccessDenied=Exception,
        NoSuchProcess=Exception,
        ZombieProcess=Exception,
        Error=Exception,
    ),
)

linux_collectors = importlib.import_module("driftwatch.app.collectors.linux.collectors")
macos_collectors = importlib.import_module("driftwatch.app.collectors.macos.collectors")
windows_collectors = importlib.import_module("driftwatch.app.collectors.windows.collectors")

LinuxSoftwareCollector = linux_collectors.LinuxSoftwareCollector
MacOSSoftwareCollector = macos_collectors.MacOSSoftwareCollector
WindowsSoftwareCollector = windows_collectors.WindowsSoftwareCollector


class FakeRegistryKey:
    def __init__(self, path: str, registry: dict[str, object]):
        self.path = path
        self.registry = registry

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeWinReg:
    HKEY_LOCAL_MACHINE = object()
    HKEY_CURRENT_USER = object()

    def __init__(self, registry: dict[str, object]):
        self.registry = registry

    def OpenKey(self, root, path):
        normalized = path.replace("\\", "/")
        if isinstance(root, FakeRegistryKey):
            normalized = f"{root.path}/{normalized}"
        if normalized not in self.registry:
            raise OSError(path)
        return FakeRegistryKey(normalized, self.registry)

    def EnumKey(self, key_handle, index: int):
        subkeys = sorted(self.registry[key_handle.path]["subkeys"])
        if index >= len(subkeys):
            raise OSError(index)
        return subkeys[index]

    def QueryValueEx(self, key_handle, value_name: str):
        values = self.registry[key_handle.path].get("values", {})
        if value_name not in values:
            raise OSError(value_name)
        return values[value_name], None


def test_linux_software_collector_parses_dpkg_output(monkeypatch):
    collector = LinuxSoftwareCollector()
    monkeypatch.setattr(linux_collectors.shutil, "which", lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)
    monkeypatch.setattr(
        linux_collectors.subprocess,
        "check_output",
        lambda *args, **kwargs: "openssl\t3.0.2\tamd64\tUbuntu Developers\ncurl\t8.5.0\tamd64\tCurl Authors\n",
    )

    records = collector._collect_dpkg()

    assert len(records) == 2
    assert records[0]["name"] == "openssl"
    assert records[0]["version"] == "3.0.2"
    assert records[0]["architecture"] == "amd64"
    assert records[0]["package_manager"] == "dpkg"


def test_windows_software_collector_parses_uninstall_registry(monkeypatch):
    registry = {
        "SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall": {"subkeys": {"DemoApp"}},
        "SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DemoApp": {
            "subkeys": set(),
            "values": {
                "DisplayName": "Demo App",
                "DisplayVersion": "2.4.1",
                "Publisher": "Driftwatch Labs",
                "InstallLocation": r"C:\Program Files\Demo App",
                "UninstallString": r'"C:\Program Files\Demo App\uninstall.exe"',
                "EstimatedSize": 4096,
            },
        },
    }
    collector = WindowsSoftwareCollector()
    monkeypatch.setattr(windows_collectors, "winreg", FakeWinReg(registry))

    records = collector._installed_software()

    assert len(records) == 1
    assert records[0]["name"] == "Demo App"
    assert records[0]["version"] == "2.4.1"
    assert records[0]["publisher"] == "Driftwatch Labs"
    assert records[0]["install_location"] == r"C:\Program Files\Demo App"
    assert records[0]["estimated_size_kb"] == 4096


def test_macos_software_collector_parses_system_profiler_json(monkeypatch):
    collector = MacOSSoftwareCollector()
    monkeypatch.setattr(
        macos_collectors.subprocess,
        "check_output",
        lambda *args, **kwargs: json.dumps(
            {
                "SPApplicationsDataType": [
                    {
                        "_name": "Safari",
                        "version": "17.4",
                        "path": "/Applications/Safari.app",
                        "obtained_from": "Apple",
                        "signed_by": ["Software Signing", "Apple Code Signing Certification Authority"],
                        "arch_kind": "universal",
                    }
                ]
            }
        ),
    )

    records = collector._applications()

    assert len(records) == 1
    assert records[0]["name"] == "Safari"
    assert records[0]["version"] == "17.4"
    assert records[0]["install_location"] == "/Applications/Safari.app"
    assert records[0]["architecture"] == "universal"
