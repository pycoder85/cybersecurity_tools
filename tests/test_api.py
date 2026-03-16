import sys
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from starlette.requests import Request

from driftwatch.app import cli
from driftwatch.app.api.server import create_app
from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import Evidence, Scan
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.demo import seed_demo_data


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def build_request(app, path: str, method: str = "GET", params: dict[str, str] | None = None) -> Request:
    query = urlencode(params or {}).encode("utf-8")
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": query,
            "app": app,
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
            "root_path": "",
            "http_version": "1.1",
        }
    )


def route_for(app, path: str):
    return next(route for route in app.router.routes if getattr(route, "path", None) == path)


def seed_software_inventory(config: AppConfig) -> str:
    with session_scope(config.database_url) as session:
        scan = session.query(Scan).order_by(Scan.started_at.desc()).first()
        record = {
            "name": "openssl",
            "version": "3.0.2",
            "publisher": "OpenSSL Project",
            "architecture": "amd64",
            "install_location": "/usr/lib",
            "hash": "software-record-1",
        }
        session.add(
            Evidence(
                host_id=scan.host_id,
                scan_id=scan.id,
                finding_id=None,
                collector_name="software",
                record_type="collector_result",
                payload_json={"records": [record], "metadata": {"count": 1}},
            )
        )
    return "software-record-1"


def test_dashboard_routes_render(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    seed_software_inventory(config)
    app = create_app(config)
    for path in ["/", "/findings", "/scans", "/software", "/evidence", "/coverage"]:
        route = route_for(app, path)
        response = route.endpoint(build_request(app, path))
        assert response.status_code == 200
        assert response.body


def test_explain_finding_endpoint(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)
    findings_route = route_for(app, "/findings")
    findings_response = findings_route.endpoint(build_request(app, "/findings"))
    assert findings_response.status_code == 200
    assert b"Findings" in findings_response.body

    summary_route = route_for(app, "/api/summary")
    summary = summary_route.endpoint()
    assert summary["host"]["hostname"] == "lab-sample-01"

    from driftwatch.app.services.database import session_scope
    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    explain_route = route_for(app, "/api/findings/{finding_id}/explain")
    payload = explain_route.endpoint(finding_id)

    assert payload["provider"] == "none"
    assert "Deterministic rule match only" in payload["explanation"]


def test_export_api_routes_and_buttons(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    software_hash = seed_software_inventory(config)
    app = create_app(config)

    findings_route = route_for(app, "/findings")
    findings_response = findings_route.endpoint(
        build_request(app, "/findings", params={"severity": "high", "status": "open"}),
        severity="high",
        status="open",
    )
    assert b"Download JSON" in findings_response.body
    assert b"/api/export/findings?format=json" in findings_response.body
    assert b"severity=high" in findings_response.body
    assert b"status=open" in findings_response.body

    scans_route = route_for(app, "/scans")
    scans_response = scans_route.endpoint(build_request(app, "/scans", params={"status": "completed"}), status="completed")
    assert b"Download CSV" in scans_response.body
    assert b"Download snapshot" in scans_response.body

    software_route = route_for(app, "/software")
    software_response = software_route.endpoint(build_request(app, "/software", params={"name": "open"}), name="open")
    assert b"Latest collected software inventory" in software_response.body
    assert b"Validate with feeds" in software_response.body
    assert software_hash.encode("utf-8") in software_response.body

    overview_route = route_for(app, "/")
    overview_response = overview_route.endpoint(build_request(app, "/"))
    assert b"Download overview snapshot" in overview_response.body

    export_findings_route = route_for(app, "/api/export/findings")
    export_findings_response = export_findings_route.endpoint(format="json", severity="high", category=None, status=None)
    assert export_findings_response.status_code == 200
    assert "attachment; filename=\"driftwatch-findings.json\"" == export_findings_response.headers["content-disposition"]
    assert b"severity" in export_findings_response.body

    export_scans_route = route_for(app, "/api/export/scans")
    export_scans_response = export_scans_route.endpoint(format="csv", status="completed", os_family="linux")
    assert export_scans_response.status_code == 200
    assert b"summary_json" in export_scans_response.body

    evidence_route = route_for(app, "/evidence")
    evidence_response = evidence_route.endpoint(build_request(app, "/evidence", params={"collector_name": "demo.seed"}), collector_name="demo.seed")
    assert b"Download JSON" in evidence_response.body
    assert b"/api/export/evidence?format=json" in evidence_response.body
    assert b"collector_name=demo.seed" in evidence_response.body

    export_evidence_route = route_for(app, "/api/export/evidence")
    export_evidence_response = export_evidence_route.endpoint(format="json", collector_name="demo.seed", record_type=None, scan_id=None, finding_id=None)
    assert export_evidence_response.status_code == 200
    assert "attachment; filename=\"driftwatch-evidence.json\"" == export_evidence_response.headers["content-disposition"]
    assert b"collector_name" in export_evidence_response.body

    export_snapshot_route = route_for(app, "/api/export/snapshot")
    export_snapshot_response = export_snapshot_route.endpoint(page="findings", severity="high", category=None, status="open")
    assert export_snapshot_response.status_code == 200
    assert "attachment; filename=\"driftwatch-findings-snapshot.json\"" == export_snapshot_response.headers["content-disposition"]
    snapshot_payload = json.loads(export_snapshot_response.body)
    assert snapshot_payload["page"] == "findings"
    assert snapshot_payload["filters"]["severity"] == "high"

    software_snapshot_response = export_snapshot_route.endpoint(page="software", name="open", severity=None, category=None, status=None)
    assert software_snapshot_response.status_code == 200
    software_snapshot_payload = json.loads(software_snapshot_response.body)
    assert software_snapshot_payload["page"] == "software"
    assert software_snapshot_payload["filters"]["name"] == "open"
    assert software_snapshot_payload["software"][0]["name"] == "openssl"


def test_findings_page_renders_workflow_ui(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    findings_route = route_for(app, "/findings")
    response = findings_route.endpoint(build_request(app, "/findings"))

    assert response.status_code == 200
    assert b"Status workflow" in response.body
    assert b"Analyst notes" in response.body
    assert b"Save status" in response.body


def test_findings_page_renders_recurrence_metadata(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    findings_route = route_for(app, "/findings")
    response = findings_route.endpoint(build_request(app, "/findings"))

    assert response.status_code == 200
    assert b"seen before" in response.body
    assert b"Occurrence:" in response.body


def test_serve_command_uses_env_host_and_port_defaults(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    class DummyScheduler:
        def __init__(self, config):
            self.config = config

        def start(self):
            captured["scheduler_started"] = True

        def stop(self):
            captured["scheduler_stopped"] = True

    def fake_run(app, host, port, log_level):
        captured["host"] = host
        captured["port"] = port
        captured["log_level"] = log_level

    monkeypatch.setenv("DRIFTWATCH_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTWATCH_HOST", "0.0.0.0")
    monkeypatch.setenv("DRIFTWATCH_PORT", "9494")
    monkeypatch.setitem(sys.modules, "driftwatch.app.services.scheduler", SimpleNamespace(ScanScheduler=DummyScheduler))
    monkeypatch.setitem(
        sys.modules,
        "driftwatch.app.services.scanner",
        SimpleNamespace(run_scan=lambda config: {"status": "ok"}),
    )
    monkeypatch.setattr(cli.uvicorn, "run", fake_run)

    exit_code = cli.main(["serve"])

    assert exit_code == 0
    assert captured["scheduler_started"] is True
    assert captured["scheduler_stopped"] is True
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9494
    assert captured["log_level"] == "info"
