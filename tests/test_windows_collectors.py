import importlib
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

windows_collectors = importlib.import_module("driftwatch.app.collectors.windows.collectors")
WindowsPersistenceCollector = windows_collectors.WindowsPersistenceCollector
_parse_windows_command_path = windows_collectors._parse_windows_command_path


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


def test_parse_windows_command_path_handles_quoted_and_unquoted_commands():
    assert _parse_windows_command_path('"C:\\Program Files\\App\\svc.exe" --service') == r"C:\Program Files\App\svc.exe"
    assert _parse_windows_command_path(r"C:\Windows\System32\cmd.exe /c whoami") == r"C:\Windows\System32\cmd.exe"
    assert _parse_windows_command_path("") == ""


def test_windows_scheduled_tasks_capture_enriched_fields(monkeypatch):
    collector = WindowsPersistenceCollector()
    csv_output = "\n".join(
        [
            '"TaskName","Task To Run","Author","Run As User","Status","Schedule Type","Last Run Time","Next Run Time"',
            r'"\DemoTask","C:\Users\Public\AppData\Local\Temp\demo.exe --run","lab","SYSTEM","Ready","Daily","3/16/2026 1:00:00 PM","3/17/2026 1:00:00 PM"',
        ]
    )
    monkeypatch.setattr(
        windows_collectors.subprocess,
        "check_output",
        lambda *args, **kwargs: csv_output,
    )

    records = collector._scheduled_tasks()

    assert len(records) == 1
    assert records[0]["category"] == "scheduled_task"
    assert records[0]["image_path"] == r"C:\Users\Public\AppData\Local\Temp\demo.exe"
    assert records[0]["run_as_user"] == "SYSTEM"
    assert records[0]["status"] == "Ready"
    assert records[0]["schedule_type"] == "Daily"


def test_windows_services_capture_registry_backed_metadata(monkeypatch):
    registry = {
        "SYSTEM/CurrentControlSet/Services": {"subkeys": {"DemoSvc"}},
        "SYSTEM/CurrentControlSet/Services/DemoSvc": {
            "subkeys": set(),
            "values": {
                "DisplayName": "Demo Service",
                "ImagePath": r'"C:\Users\Public\AppData\Local\Temp\demo-svc.exe" --service',
                "Start": 2,
                "Type": 16,
                "ObjectName": r".\LocalSystem",
            },
        },
    }
    collector = WindowsPersistenceCollector()
    monkeypatch.setattr(windows_collectors, "winreg", FakeWinReg(registry))
    monkeypatch.setattr(collector, "_service_states", lambda: {"DemoSvc": "running"})

    records = collector._services()

    assert len(records) == 1
    assert records[0]["category"] == "service"
    assert records[0]["service_name"] == "DemoSvc"
    assert records[0]["name"] == "Demo Service"
    assert records[0]["path"] == r"C:\Users\Public\AppData\Local\Temp\demo-svc.exe"
    assert records[0]["image_path"] == r"C:\Users\Public\AppData\Local\Temp\demo-svc.exe"
    assert records[0]["command"] == r'"C:\Users\Public\AppData\Local\Temp\demo-svc.exe" --service'
    assert records[0]["start_mode"] == "auto"
    assert records[0]["state"] == "running"
