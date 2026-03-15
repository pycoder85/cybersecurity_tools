from pathlib import Path
from urllib.parse import urlencode

from starlette.requests import Request

from driftwatch.app.api.server import create_app
from driftwatch.app.core.config import AppConfig
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


def test_dashboard_routes_render(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)
    for path in ["/", "/findings", "/scans", "/evidence", "/coverage"]:
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

    export_findings_route = route_for(app, "/api/export/findings")
    export_findings_response = export_findings_route.endpoint(format="json", severity="high", category=None, status=None)
    assert export_findings_response.status_code == 200
    assert "attachment; filename=\"driftwatch-findings.json\"" == export_findings_response.headers["content-disposition"]
    assert b"severity" in export_findings_response.body

    export_scans_route = route_for(app, "/api/export/scans")
    export_scans_response = export_scans_route.endpoint(format="csv", status="completed", os_family="linux")
    assert export_scans_response.status_code == 200
    assert b"summary_json" in export_scans_response.body


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
