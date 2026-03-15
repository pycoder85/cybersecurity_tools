from pathlib import Path

from driftwatch.app.api.server import create_app
from driftwatch.app.core.config import AppConfig
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.demo import seed_demo_data


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def route_for(app, path: str):
    return next(route for route in app.router.routes if getattr(route, "path", None) == path)


def test_status_update_endpoint_persists_change(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    status_route = route_for(app, "/api/findings/{finding_id}/status")
    response = status_route.endpoint(finding_id, status="investigating", redirect_to="/findings")

    assert response.status_code == 303

    with session_scope(config.database_url) as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "investigating"


def test_note_endpoint_creates_analyst_note(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    note_route = route_for(app, "/api/findings/{finding_id}/notes")
    response = note_route.endpoint(
        finding_id,
        note_text="Validated against maintenance window. Leave investigating until owner confirms.",
        author="tier1-analyst",
        redirect_to="/findings",
    )

    assert response.status_code == 303

    with session_scope(config.database_url) as session:
        finding = session.get(Finding, finding_id)
        assert finding.notes
        assert finding.notes[0].author == "tier1-analyst"
        assert "maintenance window" in finding.notes[0].note_text
